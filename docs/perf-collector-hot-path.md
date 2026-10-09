# Collector hot path: indexed expiry and inference, off-lock rendering

The collector runs on the ring-buffer poll thread, under the collector mutex. The
BPF events ring holds only a few hundred records (256 KiB, ~474 RADOS records), so
any stall in that thread drops events. Three code paths on it scaled with the
number of request groups held in memory, not with the work at hand. This change
makes them scale with the work.

## What was wrong

| # | Path | Before | Effect at production rates |
|---|------|--------|----------------------------|
| 1 | `--correlate-inferred`, every START/END marker | re-decided every pending untagged op against every request group: O(pending x groups) | 1.4 s per marker pair at 20k groups / 5k pending |
| 2 | Periodic drain (`drain_expired`, every `--otlp-flush-interval`) | rebuilt the whole request `BTreeMap` and the background `Vec` to find expired entries, then rendered every span, all under the lock | 38-43 ms under the lock to expire 1,000 of 200,000 groups; 120-128 ms to expire 20,000 |
| 3 | END-closed request groups | kept for the full idle TTL (120 s) | ~600k resident groups (~GBs) at 5k req/s |
| 4 | Per-event decode/ingest | `trans_id` copied into every event and again into the group key; op names allocated; `acting` grown in steps | 9.3 heap allocations per tagged RADOS op |
| 5 | OTLP queue | rendered `TraceDocument`s, built on the poll thread | span rendering cost paid on the poll thread |

## What changed

### Indexed expiry, detached batches (items 2 and 5)

```
requests       BTreeMap<Arc<str>, RequestBuilder>
ExpiryIndex    idle  : BTreeSet<(last_seen_ns,  key)>   closed, no END probe -> --correlation-ttl
               ended : BTreeSet<(last_seen_ns,  key)>   END arrived          -> --closed-request-grace
               open  : BTreeSet<(first_seen_ns, key)>   END still expected   -> 10 x TTL backstop
background     BTreeMap<seq, op> + BTreeSet<(event_time, seq)>
```

A drain walks each set from the oldest entry and stops at the first live one:
O(expired x log n). To keep ingest cheap, an index entry may lag behind its
group's real clock (same class, older clock). A drain that meets a lagging entry
re-files it at the real clock instead of expiring it. A move to an earlier clock or
to another class is applied at once, so nothing expires late.

`drain_expired_batch` detaches the expired groups (moves only) and counts their
diagnostics under the lock. `ExpiredBatch::into_trace_document` renders the spans.
In live OTLP mode the exporter thread does the rendering, so the queue now
carries `ExpiredBatch`es. `drain_expired` still exists and renders in place.

Queue shape: the capacity stays at **2 drains**. A larger queue of smaller units
(for example `--otlp-max-spans-per-batch`-sized chunks behind a fixed unit
capacity) bounds memory. But a production drain is 10^5-10^6 spans, the poll
thread's `try_send` loop outruns any HTTP exporter, and such a queue would drop
most of every drain. Today a drop needs the exporter to be two whole flush
intervals behind. The drop counters stay exact: `ExpiredBatch::span_count()` is
known before rendering (`1 + children` per request, `1` per background op).

### Indexed inference (item 1)

An untagged op is inferred onto a request only if that request is its unique
candidate: first among requests on the op's submit thread, then among all requests
of its pid. The predicate is unchanged, including the existing quirk that a
START-only marker (`end_ns == 0`) covers `[0, start + window]`.

```
candidates   (pid) and (pid, tid) -> CandidateSet
               from_zero  START-only markers [0, upper], by upper
               bounded    IntervalSet: per power-of-two length class, by lower
pending      id -> op                    (id = arrival order)
             (event_time, id)            which pending ops a drain finalizes
             every op      IntervalSet by pid
             NoCandidate   IntervalSet by pid
             AmbiguousAll  IntervalSet by (pid, send_tid)
             witnessed     (candidate key, id) for the 2 candidates recorded per ambiguous op
```

A query stops at the second candidate. It also cannot walk non-overlapping
requests: an `IntervalSet` keeps intervals in power-of-two length classes, each
ordered by start. An overlapping interval of length `< 2^k` must start in
`[op.start - (2^k - 1), op.end]`, so each class is a short range scan. The only
non-overlapping entries visited are class-k requests that ended shortly before
the op, a concurrency-sized set. (An earlier revision ordered candidates by
`upper` only. A query with zero or one candidate then walked every newer resident
request: 47-52 µs per such op at 20k groups, now ~0.4 µs.) START-only markers
would all fall into the top length class, so they are kept apart, ordered by
`upper`. There, every entry from `op.start` up is a candidate.

A pending op is re-decided only when its decision can change:

* A candidate appears. This can change a `NoCandidate` op (it now has one). It can
  change an `AmbiguousAll` op if the new candidate is on the op's `send_tid`,
  because the same-thread stage then has exactly one candidate. It cannot change
  an `AmbiguousTid` op, which already has two same-thread candidates.
* A candidate moves or expires. This can change an ambiguous op only if the
  candidate was one of the two recorded for it. The other two are still there.

Ops that can change are marked dirty. They are re-decided where the old code
re-decided everything (on each START/END marker and at the start of each drain)
and in arrival order. Every decision, and the order in which inferred children
join their request, is therefore identical. `src/collector/hot_path_tests.rs`
checks this differentially: 300 random event streams (overlapping, START-only,
END-only and re-STARTed requests, inverted op stamps, interleaved drains) run
through the collector and through a transcription of the old exhaustive
algorithm, and every op must end up in the same place. Removing either the
witness-driven or the same-thread-addition re-decision makes that test fail.

The pending queue is capped by `--inference-max-pending` (default 65,536, about
20-30 MB of events). On overflow the oldest pending op is decided immediately
against the current candidates and counted in the new diagnostic
`inference_pending_overflow_rados_ops`.

### Closed-request grace (item 3)

A request whose `req_state::~req_state` END has arrived is complete, except for
RADOS completions still in flight when the destructor ran. Such a group is now
exported after `--closed-request-grace` of inactivity, measured from its last
event. The default is 5 s:

* RGW waits for its own ops before a request ends, so completions after the
  destructor are the exception: asynchronous, fire-and-forget ops such as
  bucket-index `complete` calls. Those finish within one OSD round trip, normally
  milliseconds. OSD "slow request" warnings start at 30 s, so a completion more
  than 5 s late is already pathological.
* Ring-buffer delivery reorders events across CPUs by microseconds to
  milliseconds.
* Drains run only every `--otlp-flush-interval` (30 s), so a group actually lives
  between 5 s and 35 s past its last event.

A straggler after the grace is not lost or duplicated. The no-duplicate tombstone
turns a late tagged op into a background op with reason
`request_already_emitted`, and drops a late marker
(`late_request_markers_dropped`). Bounds:

* The grace never exceeds `--correlation-ttl`.
* Under `--correlate-inferred` the grace is never shorter than
  `--inference-window`, because a closed request stays an inference candidate for
  that long after its end.
* A group that is still a candidate of ANY pending inference, recorded as a
  witness or not, keeps the full TTL. Take three candidates A, B and C of one op,
  with A and B recorded. If C expired at the grace and A later at the TTL, the op
  would be inferred onto B, where the old TTL-only expiry still had B and C and
  left it ambiguous. Groups that are no pending op's candidate cannot change any
  pending decision when they go.

Groups whose END has not arrived (open) and groups on builds without the END
probe keep their old clocks.

### Allocations per event (item 4)

| Change | Saves |
|---|---|
| `trans_id: Arc<str>` on `RequestEvent`/`RadosEvent`; group keys and every index entry share it | 1 copy per correlated op and marker, plus every index key |
| `RadosOp::name: Cow<'static, str>` (only `unknown(0x..)` allocates) | 1 per op code |
| `acting` sized before copying | 0-2 reallocations |
| `ceph.rados.ops` attribute built in one buffer | 1 per op code (at render time) |

Not done: span rendering still allocates ~38 times per span (owned `String`
attribute keys and values in `SpanDocument`). That cost now runs on the exporter
thread, not the poll thread. Changing the output structs would touch the OTLP
encoder (`src/otel.rs`) and the JSON contract for no gain on the poll thread.

## Numbers

Release build, macOS (Apple silicon), `cargo test --release collector_bench --
--ignored --nocapture --test-threads=1`, three runs each. The range is shown when
runs differ by more than noise.

| Benchmark | Before | After |
|---|---|---|
| decode one RADOS event | 185-223 ns, 8.00 allocs | 169-191 ns, 6.00 allocs |
| decode + ingest a tagged RADOS op | 272-284 ns, 9.27 allocs | ~267 ns, 6.29 allocs |
| inference marker pair, 2k groups / 1k pending | 18.4-18.6 ms | 0.92-1.0 µs |
| inference marker pair, 20k groups / 5k pending | 1.41-1.43 s | 1.3-1.8 µs |
| untagged op with no candidate, 20k newer groups | 47-52 µs (first revision of this PR; the old code was also O(groups)) | 0.41-0.42 µs |
| drain, 200k groups / 1k expired: under the lock | 37-43 ms (render included) | 0.8-1.9 ms |
| drain, 200k groups / 20k expired: under the lock | 120-128 ms (render included) | 7.2-10.1 ms |
| render 1k / 20k expired groups (exporter thread) | (inside the lock above) | 5-11 ms / 120-163 ms |

## Verification

* `src/collector/hot_path_tests.rs`: the differential inference test; targeted
  tests for each re-decision path (new candidate, recorded candidate dropped out,
  new same-thread candidate, expired witness re-decided at the next marker); a
  test that a marker does not re-decide ops it cannot affect; the cap and its
  counter; a drain visiting exactly the expired index entries out of 10,000
  groups; detached-batch rendering byte-identical to an in-place drain; drained
  plus end-of-run output identical to a single end-of-run document; and the
  grace, including the coverage-regression case (a completion inside the grace
  is still a child of its request).
* `src/live/linux.rs`: a Full queue drop of an unrendered batch counts every span
  the batch would have rendered.
* The golden fixture gains only the new `inference_pending_overflow_rados_ops`
  counter. No span changed.
