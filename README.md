# 47-day-readiness-score

A tiny Go CLI that scores a hostname for **CA/B Forum 47-day TLS certificate readiness**: short-lived cert signals, chain health, AIA, OCSP/CRL, CAA, SCT and ACME surface.

> Not a CA. Educational and operations tooling. Built by [TigerTrust](https://tigertrust.io).

## Install

```sh
go install github.com/tigertrust/47-day-readiness-score/cmd/score@latest
```

Or clone and run:

```sh
git clone https://github.com/tigertrust/47-day-readiness-score
cd 47-day-readiness-score
go run ./cmd/score example.com
```

## Quick start

### Score a single host (human-readable)

```sh
score example.com
```

```
Host:  example.com:443
Score: 85 / 100
Issuer: DigiCert Global G2 TLS RSA SHA256 2020 CA1
NotAfter: 2027-01-14T23:59:59Z  (71 days remaining, validity 398 days)
Checks:
  [PASS] (-20 if fail) handshake_chain      chain verifies to system roots
  [PASS] (-15 if fail) not_expired          71 days remaining
  [FAIL] (-10 if fail) validity_leq_90      validity 398 days > 90 (informational for 2029)
  [PASS] (-15 if fail) strong_key_hash      RSA 2048, SHA256-RSA
  ...
```

### Score several hosts, JSON output

```sh
score --json api.example.com www.example.com > scores.json
```

### Non-standard port and a longer timeout

```sh
score --port 8443 --timeout 30s internal-api.example.com
```

### Generate a markdown report (great for PR comments)

```sh
score --markdown report.md tigertrust.io
```

### CI gate — fail the build if any host scores below 80

```sh
score --fail-under 80 api.example.com www.example.com
echo "exit: $?"   # 1 if any host < 80
```

### From a Go source checkout

```sh
go run ./cmd/score example.com
```

## What it checks

| Check | Weight | What it looks for |
|-------|-------:|-------------------|
| `handshake_chain` | 20 | TLS handshake succeeds and chain verifies to system roots |
| `not_expired` | 15 | `NotAfter` is more than 14 days away |
| `validity_leq_90` | 10 | Validity window ≤ 90 days (path to 47) — fails hard if > 398 |
| `strong_key_hash` | 15 | RSA ≥ 2048 or ECDSA P-256/P-384; no SHA-1 |
| `san_contains_host` | 10 | Leaf SAN includes the hostname |
| `aia_caissuers` | 10 | AIA extension with `caIssuers` URI is present |
| `ocsp_or_crl` | 5 | OCSP responder or CRL distribution point present |
| `caa_present` | 10 | Domain (or parent) has `CAA` records |
| `sct_in_cert` | 5 | Embedded SCT list (RFC 6962) — may be stapled; v1 only checks the extension |
| `http_port_80` | 5 | Port 80 reachable for the HTTP-01 ACME surface |

Score starts at 100 and subtracts the check's weight on failure. Clamped to `[0, 100]`.

### Interpreting the score

- **90+** — ready for 47-day lifecycles
- **70–89** — gaps to close; see failing checks
- **< 70** — manual review recommended

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--port` | `443` | TCP port to connect to |
| `--timeout` | `10s` | Overall TLS/HTTP/DNS timeout |
| `--json` | `false` | Emit JSON instead of human text |
| `--markdown PATH` | — | Also write a GitHub-flavored markdown report to `PATH` |
| `--fail-under N` | `0` | Exit `1` if any host scores below `N` |
| `--insecure-skip-verify` | `false` | Skip chain verification (lab only) |

## Exit codes

| Code | Meaning |
|-----:|---------|
| `0` | OK |
| `1` | At least one host scored below `--fail-under` |
| `2` | Usage / invocation error |

## JSON schema

```json
{
  "host": "example.com",
  "port": 443,
  "score": 85,
  "daysRemaining": 71,
  "notAfter": "2027-01-14T23:59:59Z",
  "issuer": "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
  "validityDays": 398,
  "policyFail398": true,
  "checks": [
    {"id":"handshake_chain","pass":true,"detail":"chain verifies to system roots","weight":20}
  ],
  "errors": []
}
```

## Use in GitHub Actions

```yaml
jobs:
  readiness:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - run: go install github.com/tigertrust/47-day-readiness-score/cmd/score@latest
      - run: score --fail-under 80 api.example.com www.example.com
```

## Context — why 47 days?

The CA/B Forum is tightening TLS certificate maximum validity from 398 days today to **47 days by 2029**. Shorter-lived certs force operators to automate issuance (ACME), harden chains (post-SC104 you must ship your intermediates, browsers may stop repairing via AIA), and keep an eye on revocation metadata. This tool scores a host against that readiness bar.

## Out of scope for v1

- Full CT log search
- ARI (`draft-ietf-acme-ari`) calls against a CA
- Multi-perspective DCV
- Windows certificate root store

## Related

- [`aia-chain-check`](https://github.com/tigertrust/aia-chain-check) — fail CI when a server does not send its full chain
- [`cert-expiry-action`](https://github.com/tigertrust/cert-expiry-action) — fail CI when a cert is about to expire

## License

Apache-2.0. See [LICENSE](./LICENSE). Responsible disclosure: [SECURITY.md](./SECURITY.md).
