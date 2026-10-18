# Third-party sources and data

| Component | Version / revision | License | Purpose |
|---|---|---|---|
| yyjson | tag `0.13.0`, commit `6447536015f3d600f3d65323b10976103b337ca7` | MIT | High-throughput, order-preserving JSON DOM |
| crawler-user-agents | Python package `1.59.0` | MIT | Exact 1,498-pattern crawler routing data |
| curl browser stack | curl `8.23.0-IMPERSONATE`, browser delta from curl-impersonate `1.5.2` commit `9607b22ccf6c440e560c5f8ad5292b8044bb6dd7` | curl/MIT plus bundled dependency notices | Content-addressed source build; HTTP/2-only production transport |

The source/data files and their upstream license texts are stored in their
respective subdirectories. The curl stack keeps the verified patch set in Git
and fetches pinned upstream source archives into a checksum-verified BuildKit
cache. The release-artifacts target retains those exact archives and publisher
signature/checksum bytes outside the runtime image. The old architecture-
specific v1.5.2 curl 8.15 mega archive remains an explicit offline control and
is rejected as a production dependency.

