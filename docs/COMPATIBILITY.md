# Facebed compatibility contract

Fastbed is a clean C implementation of the externally observable behavior of
Facebed revision `60159f365ac3a47bf7f0f71bd9c2eee090288198`.

## Public HTTP contract

| Request | Status and result |
|---|---|
| `GET /` | Landing page with the Facebed credit substituted |
| `GET /favicon.ico` | Bundled icon |
| `GET /banner.png` | Bundled banner |
| `GET /healthz` | JSON status, integer uptime/request/error counters, `no-store` |
| Any path from a non-crawler UA | `302` to the corresponding `https://www.facebook.com/` URL plus redirect HTML |
| A supported path from a crawler UA | `200`, OG/Twitter embed, `public, max-age=900`, `Vary: User-Agent` |
| A failed/unsupported crawler path | `200`, Facebook fallback card, `no-store`, `Vary: User-Agent` |

The supported parser families are generic posts/groups/permalinks/stories and
photo albums, public comments/replies, single photos, legacy `type=3` photos,
reels/short-form videos, and watch/video routes. `/share/...` is a resolution
stage, not a content parser.

## Non-negotiable invariants

- Upstream Facebook traffic is anonymous at every redirect hop.
- Only safe HTTP(S) redirect and media URLs without URL credentials are used.
- Content is emitted only after target identity is established from bounded,
  mutually consistent evidence.
- Parser and error fallback order matches the pinned oracle.
- A failed embed remains an HTTP 200 fallback and exposes no diagnostic detail.
- Raw upstream bytes used for reports remain byte-exact.
- Request state and pointers never escape their ownership lifetime.
- Full-corpus fixture replay cannot access an external network. Its canonical
  inputs are the frozen Python-oracle JSONL and the independently verified zstd
  upstream archive; the permanently retired corpus metadata tree is not
  reconstructed.

## Deliberately separate verification axes

1. HTTP/output compatibility.
2. Parser outcome and internal reason compatibility.
3. Upstream request/redirect compatibility.
4. Live Facebook acceptance under browser impersonation.
5. Concurrency and memory safety.
6. Performance and resource use.
7. Container portability and live deployment.

Passing one axis does not imply another. In particular, an offline match does
not prove live TLS impersonation, and a fast benchmark does not prove output
compatibility.

## Performance profiles

- **portable:** conservative architecture baseline, runtime feature dispatch,
  LTO, hardened release flags, suitable for amd64/arm64 images.
- **native:** host ISA tuning and profile-guided optimization for a known CPU.
- **instrumented:** sanitizer/profiling builds; never presented as production
  throughput.

Optional post-link layout, allocator, huge-page, busy-polling, or kernel-specific
experiments remain opt-in until the representative E2E benchmark shows a gain.

