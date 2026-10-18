# Fastbed concurrency and shutdown E2E

`run_concurrency_e2e.py` launches the real Fastbed executable and the separate
`concurrency_broker.py` process in a loopback-only network namespace. The
broker reuses the ordinary saved-corpus loader, so every upstream response is
size- and SHA-256-verified before Fastbed receives it. The added gate can hold
HTTP and HTTPS responses without changing `fixture_broker.py`.

Each intentional independent upstream flight receives a fresh strict corpus
occurrence counter. Retry waves share their logical flight and consume only
explicitly provisioned duplicate occurrence sets. There is no last-response
reuse: an unprovisioned retry remains a fixture overuse and fails the run.

The run covers four process lifecycles:

1. A seeded cold race for one cache key proves singleflight with exactly one
   upstream request. A second race proves warm-cache service with no new
   upstream traffic. Every response must byte-match a successful Python oracle
   output.
2. Client FIN and RST handling precede a separate queue-saturation race.
   Workers are held at the upstream gate, the full configured queue is admitted,
   excess clients receive the exact overload contract, and health/browser paths
   remain responsive. The gate then releases the admitted work and every 200
   body must match the oracle.
3. SIGTERM begins graceful drain while active requests are gated. Releasing
   them inside the grace window must yield exact successful responses and a
   zero process exit.
4. A second SIGTERM leaves active requests gated past the grace deadline. The
   process must remain alive during the grace window, then return the exact
   forced-shutdown response, cancel the upstream work, and exit zero within the
   allowed slack. The gate also proves the configured transport retry timeline:
   with the current 25-second attempt timeout, 250 ms retry delay, two-attempt
   cap, and 30-second grace window, each request has exactly two upstream
   arrivals backed by two explicitly provisioned occurrences per logical
   flight. An extra arrival, overuse, or off-timeline retry fails the run.

Clients bind across at least four explicit `127/8` source addresses. The seed,
per-client source address, delay, timing, status, headers, body hash, broker
lifecycle, process samples, commands, exit status, and signal-to-exit timing
are retained in the artifact.

## Run

Build Fastbed first, then use a known successful medium-hard corpus line and
its Python offline result. The example group post has a 2.2 MiB upstream
fixture, Unicode metadata, and a rendered video:

```sh
e2e/run_concurrency_e2e.sh \
  build-release/fastbed \
  /home/pie/src/facebed/fulltest/corpus \
  --python-results /home/pie/src/fastbed/artifacts/python-oracle-full-20261016/results.jsonl \
  --line 521 \
  --output /tmp/fastbed-concurrency-e2e
```

The harness defaults match the current server defaults: a 64-entry work queue
and a 30-second graceful-shutdown deadline. Future or deployment-specific
server options can be passed opaquely without changing this harness. Keep the
harness expectations aligned with the binary settings; arguments beginning
with `-` use the joined form:

```sh
  --queue-limit 16 \
  --grace-seconds 2 \
  --fastbed-arg=--work-queue-limit=16 \
  --fastbed-arg=--graceful-shutdown-seconds=2
```

Those example production option names are intentionally not assumed by the
runner; use the spellings implemented by the finalized binary.

For a focused implementation check, `--scenario saturation` exercises the
strict independent-flight provisioning, FIN/RST handling, queue limit, and
fast paths without running the two shutdown lifecycles. Omit `--scenario` for
the required complete artifact.

If the transport timeout, retry delay, or attempt cap changes, align the
corresponding harness arguments as well. The runner rejects grace deadlines
too close to a retry boundary because scheduler jitter would make the expected
attempt count ambiguous.

## Verify the artifact

The output directory is new-only. A passed run contains `manifest.json`,
`responses.jsonl`, per-generation broker reports, representative response
bodies, process logs, `process_samples.jsonl`, `commands.jsonl`, and a checksum
inventory. Verify every retained byte with:

```sh
(cd /tmp/fastbed-concurrency-e2e && sha256sum -c SHA256SUMS)
```

On failure the same directory is finalized with `failure.json`, a failed
manifest, logs, partial scenario evidence, and valid `SHA256SUMS` rather than
discarding the race that exposed the problem.
