# Bugfix: long-session memory and data integrity

[Back to documentation](README.md)

rgwtrace runs as root next to production OSDs, and a session can last hours at
thousands of requests per second. Four defects only showed up at that scale.
This page covers what happened, why, and the fix for each.

## 1. `--output json` never released memory

**What happened.** The live loop only drained expired requests out of the
collector when `--output otlp` was set. With `--output json` (the default), every
request group, RADOS op, and background op stayed in memory until exit, at about
3 KB per request: tens of GB per hour at production rates, with the OOM killer
choosing among the tracer and the OSDs on the same host. At exit, `main` then
built a full `serde_json::Value` copy of the trace and a pretty `String` of it,
so the peak was three copies.

**Fix.**

- `--output jsonl` (new) drains on the same interval as OTLP (`--flush-interval`,
  an alias of `--otlp-flush-interval`) and writes each drain as one compact
  `{dwarf, trace}` line, flushed per line. A final line at exit carries what was
  still in flight and the final counters. Memory is bounded by rate x TTL.
- `--output json` keeps its single-document format and gets a cap,
  `--max-buffered-events` (default 100,000 buffered request groups and RADOS ops,
  about 100 MB). Past the cap, new requests and ops are dropped, counted in
  `buffer_full_dropped_markers` / `buffer_full_dropped_rados_ops`, and warned about
  once. Markers for a request already held still land, so held requests can
  complete. The flag is rejected with the streaming modes.
- The final document is written straight to stdout through a `BufWriter`, one
  span at a time (`src/output.rs`). The bytes are identical to the old output,
  including the sorted key order the `Value` path produced; a unit test compares
  the two renderings.

**Why a cap and not "refuse without `--timeout`".** A `--timeout` of several hours
is as unbounded as no timeout, so refusing would not bound memory. A cap does, in
every case, and an operator who hits it gets a counted, logged signal that points
at `jsonl`. Without `--timeout`, `--output json` warns at startup.

## 2. The no-duplicate tombstone saturated

**What happened.** Every exported request key went into one never-reset Bloom
filter (2^26 bits, 20 hashes), so that a straggler could never re-create an
exported group and emit a second span with the same span id. Its false-positive
rate grows with the number of keys: about 1e-7 at 2M, 35% at 10M, 91% at 18M. Each
false positive drops a fresh request's START and END markers and demotes its ops
to background (`request_already_emitted`). A multi-hour session reaches those
numbers.

**Fix.** Fixed memory, a false-positive rate that does not grow with session
length, and the same no-duplicate guarantee (`EmittedRequests`,
`src/collector.rs`):

1. **Exact set for force-expired open requests.** A request force-expired at the
   lifetime backstop (its END never arrived) can still produce its END, and ops
   while it lives, at any later time. These are rare and kept exactly while
   events keep arriving. An entry idle for a whole Bloom generation moves into
   the Bloom filter. The set is capped at 65,536 entries; overflow goes to the
   Bloom filter (`emitted_open_tombstone_overflows`).
2. **Two rotating Bloom generations** (8 MiB each) for all other keys. Lookups
   check both, inserts go to the current one, and when it reaches 2M keys the
   older one is dropped (`emitted_tombstone_rotations`). Rotation is by count, so
   no generation passes its design point: the rate a lookup sees stays below
   about 2e-7 forever.
3. **A horizon.** Rotation forgets keys, so it needs a proof that nothing can
   arrive for a forgotten key and look new.

### Why forgetting is safe

Let `horizon_ns` be the time the oldest surviving generation started.

- Every key in a dropped generation was inserted before `horizon_ns`, because a
  generation's keys are all inserted before the next generation starts.
- A key is inserted when its group is exported, at drain time `T_x`.
- A request starts before it is exported. A closed group expires only when
  `last_seen <= now - ttl`, and `last_seen` is at least the request's start; an
  open group expires only when `first_seen <= now - 10 x ttl`. So
  `start <= T_x - ttl < horizon_ns`.

So every event for a forgotten key belongs to a request that started before
`horizon_ns`. The collector rejects an event when all of these hold: the key is
not a group it holds, the tombstone does not remember it, and the request
started before `horizon_ns`. Markers are dropped; ops become background spans
with reason `request_outside_tombstone_horizon`. Both are counted in
`tombstone_horizon_rejections`.

The request start comes from:

- `start_ns` on every marker. The END marker carries it too, from `get_handler`.
- The `trans_id` of a RADOS op, when it has RGW's shape. RGW builds every
  transaction id as `tx%021llx-%010llx-<zone>` from a counter and `time(NULL)`
  at the start of request processing (`zone_unique_trans_id`), so the second
  field is the request's start in unix seconds.

The `trans_id` source matters when the END probe is not attached. Nothing then
revokes a request context, so a context left on an RGW thread can stamp an old
request's `trans_id` onto a fresh op at any later time. The op's own timestamps
say nothing about how old its request is.

The `trans_id` timestamp is RGW's wall clock, while `horizon_ns` is on the trace
clock (boottime plus the offset sampled at startup). The `- ttl` margin above
absorbs a divergence of up to `--correlation-ttl` (120 s by default) between the
two.

### What remains unproven

- An op whose `trans_id` is not in RGW's shape, for a key that was rotated out.
  This needs a force-expired request that stayed alive and silent for a whole
  generation, or a stale-context stamp more than two generations late.
- A wall-clock step larger than `--correlation-ttl` since startup, for an op
  whose request was rotated out.

Both need at least 2M exported requests in between, and both would show up as a
duplicate span id, which `verify-rgwtrace-json.py` checks for.

**Legitimate events the horizon rejects.** A request the collector never saw
(its START was lost, or it began before tracing) that started more than a full
generation of exported requests ago. Dropping or demoting it is the same
fail-closed trade the tombstone already made.

## 3. One failed OTLP batch disabled export for the rest of the run

**What happened.** The exporter thread returned on the first batch that failed
after its retries. That batch and up to two queued behind it were lost, and no
counter recorded it. The live loop then found the channel disconnected, latched
export off, kept the stranded batch in memory, and never drained again. From
then on the collector grew exactly as in finding 1.

**Fix.**

- The worker never exits on a send failure. A batch that fails for good is
  counted in `otlp_export_failed_batches` / `otlp_export_failed_spans` (lost
  spans), a warning is logged, and the worker takes the next drain.
- A non-retryable response (4xx other than 429) loses only that batch; the next
  batch of the same drain is tried, because the endpoint answered promptly.
- Exhausted retries (connection errors, timeouts, 5xx, 429) lose that batch and
  the rest of the same drain without trying them. Otherwise an unhealthy
  endpoint would block the worker for `batches x (retries + 1) x timeout` while
  drains queue up behind it.
- No error class latches export off. A misconfiguration 4xx (bad auth, wrong
  path) costs one prompt request per drain, every loss is counted and warned,
  and a fix on the backend side takes effect without restarting the tracer.
- If the worker thread dies anyway (a panic), drained batches are counted as
  lost and draining continues, so memory stays bounded. The old "retain the
  batch" path is gone.
- The final export is unchanged: any failed batch fails it, and the end-of-run
  trace is dumped to stdout.

## 4. Expiry used the wall clock

**What happened.** Event timestamps are CLOCK_BOOTTIME plus a unix offset fixed
at startup, but expiry compared them against a fresh CLOCK_REALTIME. An NTP step
back stalled expiry, because nothing looked old enough. A step forward made open
requests look older than they were and force-expired them early with derived
ends.

**Fix.** Expiry reads `TraceClock::now_ns()`: CLOCK_BOOTTIME plus the same
startup offset as the events (`src/live/linux.rs`).

## Tests

- `collector.rs`: the false-positive rate stays flat at 10x the generation
  capacity, and a never-rotating filter at that load is shown to saturate. Also
  covered: horizon coverage of every forgotten key; a live force-expired request
  across several rotations (no re-emission, plus a coverage-regression check that
  the fresh requests all stayed correlated); a silent one rejected by the horizon;
  a stale RGW `trans_id` on a fresh op rejected after rotation; `trans_id`
  parsing; periodic draining bounding the request map; the JSON buffer cap.
- `output.rs`: the streamed JSON is byte-identical to the legacy rendering, and
  JSONL is one document per line.
- `otel.rs`: periodic failures are counted rather than fatal; a rejected batch
  does not stop the next; exhausted retries abandon and count the rest; the final
  export still fails.
- `live/linux.rs` (Linux only): the worker survives a failed batch and exports
  the next drain; a disconnected worker is counted, not retained; the expiry
  clock is boottime-based.
- `tests/cli_dry_run.rs`: JSONL dry run, buffer-cap validation, the
  `--flush-interval` alias.
- `verify-rgwtrace-json.py --self-test`: merges a JSONL stream and catches a span
  repeated across lines, a wrong per-line `spans_produced`, and a cumulative
  counter going backwards.
