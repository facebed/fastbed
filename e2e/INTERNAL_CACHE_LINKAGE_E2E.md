# Internal-cache and linkage E2E

This gate runs the same statically linked Fastbed binary twice against 16
medium-hard archived Facebook posts. The default variant has no cache flag;
the second uses `--internal-cache`. Two randomized blocks send 128 concurrent
requests per variant through the real Fastbed HTTP server and loopback HTTP/TLS
archive broker. Every public response is status/body-hash checked.

For each completed run, compare the broker report in
`hook-measure-00.stdout` with `latency.records.tsv`:

- `default-no-cache` must make one upstream call per request (128 total);
- `internal-cache` must make one upstream call for each distinct target index,
  with no target called twice;
- both variants must complete 128/128 exact responses with no transport,
  protocol, status, hash, or timeout error;
- server stderr must state `internal cache disabled` or
  `internal cache enabled` consistently with the variant.

The release build separately runs `cmake/VerifyBundledStaticLinkage.cmake`.
Its report must list only libc, libstdc++, libgcc, and PCRE2 as direct dynamic
dependencies and must confirm compiled-in curl-impersonate, yyjson,
libmicrohttpd, and libyaml symbols. The same verifier must reject a diagnostic
binary linked to dynamic system libcurl. The release binary must reject every
verification-only option, omit those option names from its compiled string
table, and retain `--internal-cache`; the verification build must expose the
guarded options. The gate also proves that the removed `build.sh --run` mode
fails with usage status 2. With both prefix environment variables unset,
`build.sh` must resolve the verified repo-local defaults and complete a native
release build.

Copy this plan to a temporary input directory, replace `/ABS`, validate it with
`benchmark/run_matrix.py --check-plan`, and execute it in a loopback-only user
and network namespace. The matrix artifact snapshots the plan, binaries,
inputs, raw records, broker bundle/reports, harness, schedule, host samples,
manifest, and `SHA256SUMS`.
