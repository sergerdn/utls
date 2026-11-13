# TLS 1.3 certificate transcript reproducer

This standalone Surf client exercises the Safari TLS path affected by a TLS 1.3 certificate transcript defect. Its
nested module is `example.com/certificate-transcript`, requires Go 1.27, and pins Surf `v1.0.236` with
`github.com/enetx/utls v1.0.6` as the published, affected baseline.

**Live verification:** direct IPv4 requests reproduced the failure and verified the fix on 2026-11-13, using Go 1.27.4
on darwin/arm64. The captured results below compare the pinned published baseline with this checkout’s local fix.

## Live baseline

From the repository root:

```bash
cd examples/certificate-transcript
go version
go env GOOS GOARCH
go list -m github.com/enetx/surf github.com/enetx/utls
go run . -url https://example.com/ -network tcp4
```

The baseline module listing must show `github.com/enetx/surf v1.0.236` and `github.com/enetx/utls v1.0.6`, with no `=>`
replacement.

Record the version and module output alongside the request result. The first run may download dependencies. The default
URL is `https://example.com/`; `-url` selects another HTTPS endpoint. The default network is `tcp4` (IPv4);
`-network tcp6` selects IPv6, and `-network tcp` allows either address family.

The client uses `SecureTLS()`, `Proxy("")`, a 20-second timeout, and `JA().Safari26_3()`. Its custom dialer selects the
requested address family, and `NotFollowRedirects()` disables redirects. The program requires an absolute HTTPS URL and
one of the three supported network values. Certificate verification is enabled, and ambient proxy settings are disabled:
these commands make direct connections. A successful request prints the HTTP status, negotiated TLS version, and ALPN. A
request failure exits nonzero.

Captured baseline output (banner on stdout, error on stderr):

```text
Safari 26.3; network=tcp4; certificate verification enabled; proxy disabled
request: Get "https://example.com/": uTLS.HandshakeContext() error: tls: invalid signature by the server certificate: ECDSA verification failure
exit status 1
```

A live failure depends on the server's certificate message, including its extension order, and on reaching that server.
The IPv6 run requires an AAAA record and working IPv6 connectivity. A routing, DNS, timeout, or trust failure does not
establish this bug. A successful baseline request does not disprove it: the endpoint may select a different handshake or
certificate representation. Safari advertises zlib certificate compression, but the server may send an ordinary,
uncompressed `Certificate` message.

## Compare the local fix

Stay in `examples/certificate-transcript` and run the same request using the checkout's uTLS implementation:

```bash
(
  set -eu
  transcript_mod_dir=$(mktemp -d)
  trap 'rm -rf "$transcript_mod_dir"' EXIT
  cp go.mod "$transcript_mod_dir/fixed.mod"
  cp go.sum "$transcript_mod_dir/fixed.sum"
  go mod edit -modfile="$transcript_mod_dir/fixed.mod" -replace=github.com/enetx/utls=../..
  go list -modfile="$transcript_mod_dir/fixed.mod" -m github.com/enetx/surf github.com/enetx/utls
  go run -modfile="$transcript_mod_dir/fixed.mod" . -url https://example.com/ -network tcp4
)
```

The replacement `../..` resolves from the example's module root to the repository root, even though `fixed.mod` is in a
temporary directory. The module listing must show `github.com/enetx/utls v1.0.6 => ../..`. The temporary modfile and its
matching `fixed.sum` keep the committed example module unchanged. Use the same URL and address family in both runs.

Captured fixed output (exit status 0):

```text
Safari 26.3; network=tcp4; certificate verification enabled; proxy disabled
HTTP status: 200
TLS: TLS 1.3; ALPN: "h2"
```

Observed direct-request results on 2026-11-13:

| Endpoint                                             | Network | Published v1.0.6                 | Local fix                        |
|------------------------------------------------------|---------|----------------------------------|----------------------------------|
| `https://example.com/`                               | IPv4    | 3/3 ECDSA verification failures  | 3/3 HTTP 200, TLS 1.3, ALPN `h2` |
| `https://www.cloudflare.com/cdn-cgi/trace` (control) | IPv4    | 3/3 HTTP 200, TLS 1.3, ALPN `h2` | 3/3 HTTP 200, TLS 1.3, ALPN `h2` |
| Both endpoints                                       | IPv6    | Both attempts failed before TLS  | Both attempts failed before TLS  |

The four IPv6 attempts, one per endpoint and variant, all failed with `connect: no route to host`. This is an
environment limitation; no IPv6 TLS result was established. Repeat the control by selecting its URL with `-url` in both
commands.

## Deterministic regression tests

Run these commands from the repository root. The selected tests construct certificate messages and signatures in memory,
without contacting an external server. The root package's `TestMain` still opens a loopback listener and checks OpenSSL,
so the test harness requires both loopback socket access and a supported `openssl` executable on `PATH`.

```bash
go version
openssl version
go test -count=1 -run '^TestTLS13ServerCertificateTranscript(RejectsInvalidSignature)?$' .
```

Observed locally with Go 1.27.4 on darwin/arm64: the archived baseline failed four valid-signature cases, and the fixed
checkout passed ten race-enabled runs using the command below. Both the published-baseline example and the local-fix
example passed build and vet.

```bash
go test -race -count=10 -run '^TestTLS13ServerCertificateTranscript' .
```

Both regression tests should pass with the fix. The positive cases cover OCSP/SCT extension order, an ignored extension,
optional `CertificateRequest`, compressed certificates, and the ordinary `Conn` path. The negative test corrupts a
signature and verifies that it is rejected; preserving the transcript must not bypass signature verification.

To demonstrate failure against the unpatched baseline, export it to a temporary directory and copy in only the
regression test. The commit below is the published `v1.0.6` baseline, so the comparison does not depend on a moving
branch.

```bash
(
  set -euo pipefail
  transcript_baseline=$(mktemp -d)
  trap 'rm -rf "$transcript_baseline"' EXIT
  baseline_ref=ec1e9f2bb7793496586955cb4297849419d9eb9e
  git rev-parse "$baseline_ref"
  git archive "$baseline_ref" | tar -x -C "$transcript_baseline"
  cp handshake_client_tls13_transcript_test.go "$transcript_baseline/"
  cd "$transcript_baseline"
  go test -count=1 -run '^TestTLS13ServerCertificateTranscript(RejectsInvalidSignature)?$' .
)
```

Expected on the affected baseline: a nonzero test exit with `ECDSA verification failure` for valid signatures over
certificate messages whose original bytes are not preserved. The fixed checkout must pass the same tests. This
comparison does not switch branches, create a Git worktree, or modify downloaded module sources.

## Cause and fix

TLS 1.3 authenticates the received handshake bytes. Re-marshaling an uncompressed `Certificate` can reorder its
certificate extensions or drop ignored extensions, changing the transcript hash even though the certificate itself has
not changed. The server's valid `CertificateVerify` signature then fails against the reconstructed transcript.

The fix passes the transcript into `readHandshake`, hashing the original received bytes after successful decoding
instead of reconstructing the decoded message. It also removes the later compressed-certificate transcript write, so a
`CompressedCertificate` is hashed exactly once in its received form. Certificate trust checks and `CertificateVerify`
signature verification remain enabled.
