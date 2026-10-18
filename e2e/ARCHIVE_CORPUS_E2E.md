# Archive-backed full-corpus E2E

`run_corpus_e2e.py` drives the real Fastbed process through loopback HTTP/TLS.
The canonical path no longer depends on the permanently retired
`facebed/fulltest/corpus` tree. It uses:

- `artifacts/python-oracle-full-20261016/results.jsonl` for ordered corpus URLs,
  expected HTTP outputs, row-local upstream request traces, transport errors,
  and known fixture misses;
- `facebed/fulltest/upstream_archive/bodies.jsonl` and its content-addressed
  zstd containers for exact upstream response bytes; and
- `archive.json` plus `verification.json` to bind the complete archive and body
  index before the broker starts.

The broker preserves distinct HEAD/GET operations, repeated occurrences,
redirect hops, recorded final URLs, transport disconnects, and row selection.
It never searches another row. Decompressed bytes are checked against both the
oracle size and archive SHA-256 before use. Known oracle fixture gaps, new
Fastbed gaps, exhausted occurrences, and archive-integrity failures are counted
separately in every artifact.

The failure model for this adapter is in
[`docs/FAILURE_MODEL.md`](../docs/FAILURE_MODEL.md#archive-backed-full-corpus-replay).

## Run

Build a static verification binary first with
`FASTBED_VERIFICATION_BUILD=ON`; release/optimized binaries intentionally omit
the replay-port and resource-override arguments. From `/home/pie/src/fastbed`,
a complete run is:

```sh
parent_netns="$(readlink /proc/self/ns/net)"
unshare --user --map-root-user --net sh -c '
  ip link set lo up
  exec python3 e2e/run_corpus_e2e.py \
    build-replay/fastbed \
    /home/pie/src/facebed/fulltest/upstream_archive \
    --python-results artifacts/python-oracle-full-20261016/results.jsonl \
    --output artifacts/archive-corpus-full \
    --parent-netns "$1"
' sh "$parent_netns"
```

Use `--lines` with a comma-separated source-line list for a medium-hard gate.
Selection remains in oracle source order. `--resume` accepts an existing output
only when the binary, runner, broker, oracle, archive indexes, and ordered
selection still match its immutable `start-state.json`.

The repeatable evidence is `manifest.json`, `results.jsonl`, exact rendered
bodies under `outputs/`, service/broker logs, and `SHA256SUMS`. A successful
process exits zero only when body, status, relevant headers, and upstream trace
all match, with no new gap, overuse, or integrity error. Shared historical gaps
remain visible but do not make an otherwise exact replay fail.
