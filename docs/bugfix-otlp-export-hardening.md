# Bugfix: harden the OTLP exporter

rgwtrace runs as root on storage nodes and ships traces over OTLP/HTTP to a
collector that usually needs credentials. A review of that path found six
things, fixed together here because they all live in how the HTTP client is
built and what it is allowed to say.

## What happened

1. **Redirects were followed.** The reqwest client used the default policy
   (up to ten redirects). A `307`/`308` from the endpoint -- a load balancer
   pointing at another host, or an `https` -> `http` downgrade -- was followed
   with the request intact: the operator's `X-Api-Key`/`X-Scope-OrgID`
   headers and the trace body went wherever `Location` said.

2. **Secrets reached the log.** The endpoint URL was logged on every export
   attempt at debug level and quoted in every send error, userinfo and query
   string included; reqwest's own error text renders the URL too. The error
   response body was read without a bound and logged verbatim on every retry,
   newlines and escape sequences included.

3. **Credentials had to be on argv.** `--otlp-header 'Name:Value'` was the only
   way to send a header, and argv is readable by every local user through
   `/proc/<pid>/cmdline`.

4. **A client per document.** A new `reqwest::blocking::Client` -- a new
   connection pool and, over https, a new TLS handshake -- was built for every
   exported document, i.e. every periodic drain.

5. **No private-CA option.** A collector with an internal certificate could
   only be reached by turning off TLS and using `http://`.

6. **Sensitive attributes exported verbatim.** `ceph.rados.object` carries S3
   object keys, `<uid>.buckets` user names, tenant names and access-key ids
   (`AuthMeta` objects), to a default endpoint that is plain http.

## The fix

- **No redirects** (`reqwest::redirect::Policy::none()`). A `3xx` is a fatal,
  non-retried export error that tells the operator to point `--otlp-endpoint`
  at the final URL. Test: a mock `307` to a decoy listener; the decoy must
  never see a connection.

- **Log redaction.** The endpoint is parsed once; only its
  scheme/host/port/path is logged (`redact_url`). reqwest's error chain is
  scrubbed of the URL as given, as reqwest renders it (userinfo stripped,
  query kept -- which the first version of the test caught), the bare query
  string, and the password (`scrub_url_secrets`). Error bodies are read to at
  most 1 KiB off the socket and control characters are escaped
  (`body_excerpt`). The regression test captures the log at debug level and
  asserts that neither header values nor URL secrets appear on the success,
  retry and connection-failure paths.

- **Header sources** (`src/otlp_headers.rs`): `--otlp-header-file` (one
  `Name: Value` per line, `#` comments; refused if world-readable) and the
  OpenTelemetry `OTEL_EXPORTER_OTLP_HEADERS` / `OTEL_EXPORTER_OTLP_TRACES_HEADERS`
  variables (`k=v,k2=v2`, percent-decoded; the traces variable replaces the
  generic one, per the spec). The sources merge by case-insensitive name with
  **file > env > flag** precedence -- the inverse of how exposed each is, so a
  secret is never overridden by what is on the command line, while non-secret
  headers can stay there. Errors name the source and position, never a value.
  The world-readable check is an error rather than a warning: a warning
  arrives after the exposure.

- **One `otel::ExportClient` per exporter**, owning the reqwest client, the
  validated header map and the timeout; built in `main` at startup (before
  DWARF loading, so configuration errors fail fast) and once for the live
  exporter thread, and passed through `ExportConfig::client`. Test: two
  documents through one client arrive on one keep-alive connection.

- **`--otlp-ca-cert <pem>`** adds a PEM bundle via `add_root_certificate`
  (rustls). A missing, non-PEM or certificate-less file is refused at startup
  with an error naming the flag; `tests/cli_otlp_config.rs` checks this at the
  binary level, against a committed self-signed fixture
  (`tests/fixtures/otlp_test_ca.pem`, certificate only).

- **`--redact-object-names`** replaces every `ceph.rados.object` with the
  FNV-1a 64 hash of the name as 16 hex digits -- the same hash the span ids
  use -- and adds `rgwtrace.redacted = "ceph.rados.object"`. It is applied at
  the single point RADOS attributes are built, after `classify_rados` has run
  on the raw name, so it covers correlated children, background spans and
  their `rados.op` event, the final document and periodic drains, JSON and
  OTLP. Off by default; the golden fixture pins the verbatim shape.

## Deliberately not done

Background spans still carry their attribute list twice (on the span and on
its `rados.op` event). Dropping the copy is a consumer-visible change to the
output contract that the golden fixture, the e2e verifier
(`validate_background_event`) and any backend query on event attributes
depend on; it belongs in its own change with those updated together.

## A note on the test harness

The log-capture test first used a scoped `tracing` subscriber
(`with_default`) and passed alone but failed under the parallel runner with
an empty capture. tracing-core computes a callsite's cached interest from
the *current thread's* default when only one dispatcher is registered; a
concurrently running test that logs with no subscriber recomputes the shared
cache as "never interested". The helper now installs one global subscriber
per test binary that writes to a thread-local buffer, so interest is always
computed against a real subscriber and each test reads only its own thread's
output.
