# Scratch image live canary

This bounded release gate starts the exact scratch image under the documented
container restrictions and sends three crawler requests through live Facebook:
a photo route, a reel route, and a permalink route. It exists to prove the
static musl resolver, injected container DNS files, copied CA bundle,
curl-impersonate TLS stack, route dispatch, and renderer together.

## Failure model

The gate fails when:

1. The image tag changes identity during the run or the artifact does not bind
   the immutable image ID and copied runtime binary.
2. The scratch container cannot resolve Facebook, validate its certificate,
   negotiate the pinned browser fingerprint, or follow a safe redirect.
3. A transport failure is hidden behind Fastbed's normal HTTP 200 fallback.
   Every selected route must return the cacheable parsed-embed contract, not
   merely status 200.
4. The three requests collapse onto one parser family, lose `Vary: User-Agent`,
   return a non-HTML response, or omit OG metadata.
5. Health counters do not advance by exactly three requests, record an error,
   or the process fails to shut down cleanly under the locked-down policy.
6. A response, header set, log, command, image record, binary hash, or harness
   input is missing from `SHA256SUMS`.

Facebook content and routing can change after a successful run. This gate is a
time-bounded transport/acceptance result, not a permanent response fixture. It
must not record credentials, cookies, configuration secrets, or CAPTCHA data.

## Run

```sh
python3 e2e/run_scratch_live_canary.py \
  --image fastbed:scratch-static-amd64 \
  --output artifacts/fastbed-scratch-live-canary-$(date -u +%Y%m%d)-01

(cd artifacts/fastbed-scratch-live-canary-$(date -u +%Y%m%d)-01 && \
  sha256sum -c SHA256SUMS)
```

The output directory must not exist. The runner removes only its uniquely
named container and leaves the image and unrelated Docker state untouched.
