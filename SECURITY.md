# Security Policy

revkit parses untrusted, potentially malicious input by design. A crafted file that makes revkit
execute code, write outside its output directory, or hang indefinitely is a security issue.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately via
[GitHub Security Advisories](https://github.com/h050sh/easy-revkit/security/advisories/new).
Include the revkit version, a description of the impact and a minimal reproducer (or its hash).

## Safe usage

- Always analyse untrusted samples inside an isolated VM or container.
- revkit itself never executes the sample, but optional external tools it invokes
  (Ghidra, jadx, ilspycmd, upx, pycdc) have their own attack surface.
