# Security policy

## Supported versions

The `main` branch and the latest tagged release receive security fixes.

## Reporting a vulnerability

Please email **security@tigertrust.io** with a description of the issue, steps
to reproduce, and any proof-of-concept. We acknowledge reports within 3
business days and aim to ship fixes within 30 days for critical findings.

Do **not** file public GitHub issues for vulnerabilities.

## Scope

This tool makes outbound TLS, HTTP and DNS requests to hosts you specify on the
command line. It does not open listening sockets, store credentials, or
transmit data to third parties. Any deviation from that is in-scope.
