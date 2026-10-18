# curl 8.23 HTTP/2-only impersonation stack

Production images build official curl 8.23.0 with the browser-impersonation
delta derived from curl-impersonate v1.5.2 commit
`9607b22ccf6c440e560c5f8ad5292b8044bb6dd7`. Every source, signature/checksum
file, and patch is content-addressed before extraction or application by
`tools/build-curl-impersonate.sh`.

The production profile contains only the `http` and `https` URL protocols. It
retains BoringSSL, ECH, HTTPS RR, HTTP/2, threaded DNS, IDN, IPv6, proxy,
cookies, MIME, gzip/deflate, Brotli, and Zstandard. HTTP/3/QUIC is deliberately
absent until it has an authoritative wire-fingerprint oracle. The build fails
if an nghttp3/ngtcp2 archive, `HTTP3`, `UnixSockets`, an unexpected protocol, or
a missing required feature appears.

## Production patches

The five patch files are exact copies of the verified interim curl 8.23 build:

| Patch | SHA-256 | Purpose |
|---|---|---|
| `0001-curl-8.23.0-v1.5.2-production.patch` | `5b7034eb94c458eac87a775b6306401b875d7baae13f1aecc443554c8e65c083` | Browser impersonation API/profile port on the official curl 8.23.0 release source |
| `0002-boringssl-v1.5.2-base.patch` | `f6315235ea19778fbca8b6544732024f854f38eaa5a600d621f1ac55b4e22424` | Exact v1.5.2 BoringSSL fingerprint delta |
| `0003-boringssl-CVE-2026-35189.patch` | `2c9277a0576c6ed943386490c1ed53ba2e5b8ccef2f1ec4c0c326e4e2177c2dd` | Prerequisite `5386d908a663a424d154cbae7f76f2266c60c2fe` plus fix `9b639f5b3b086508c03f6a4a1792e4a6043777ac` |
| `0004-brotli-v1.5.2.patch` | `d59ec1994ae6285222f65dd7192c2cbcbc0d0ae6c85eb5fce1cae735010f4d4f` | v1.5.2 Brotli portability delta |
| `0005-nghttp2-1.68.1-outbound-priority-compat.patch` | `bf30fc417c26afcaafe732629073db13fc1563edcd7964ee7c1fbf300f7eb3f3` | Restore only outbound RFC 7540 priority serialization removed in nghttp2 1.65 |

nghttp2 1.68.1 already contains the CVE-2026-27135 fix. The compatibility
patch touches `nghttp2_submit.c`, while the security-relevant
`nghttp2_session.c` remains at SHA-256
`8d9c0be1199ab6181d0998a78e49dc34fdbdb75d27922f2a4f66c923b1fd557a`.
Curl 8.23.0 is newer than the releases affected by CVE-2026-92392. The pinned
BoringSSL revision still requires the explicit CVE-2026-35189 backport.

All patches are applied with zero fuzz. The builder then checks selected
post-patch source hashes, the exact protocol/feature inventory, both forms of
the `chrome146` direct API call, unknown-profile rejection, exported symbols,
the target ELF architecture, and the absence of HTTP/3 archives.

The output consists of ordinary split static archives. Do not collapse them
with `ld -r --whole-archive`; doing so prevents section garbage collection from
discarding unused TLS and codec functions. `COMPONENTS.tsv`,
`BUILD-MANIFEST.txt`, license files, `SOURCE-OFFER.txt`, the builder and exact
patches, and the complete prefix `SHA256SUMS` travel with release metadata.

The official v1.5.2 mega archives remain offline comparison controls only:

- amd64: `01e7d4befa38d5939559a1109a35061a4cc58e989ebf55588a62bcea8dbf8e7b`
- arm64: `8900c5a54cf0c386ba9c55be7542cbe484bca1422ed382599877d20412401ec5`

Their curl 8.15 code and legacy dependency closure must never be used in a
production image. The corresponding historical patches are isolated under
`patches/control-curl815/` and are not copied into the production rebuild kit.
