# Security policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

Scheme 1 wire format is stable for 0.1.x. Report a bug that breaks that layout as a vulnerability.

## Reporting

Use GitHub private vulnerability reporting:

https://github.com/Primatio/vaultseal/security/advisories/new

Do not open a public issue, pull request, or discussion that contains key material, plaintext, or a member private key.

Acknowledgement target: 3 business days.

## What to include

- Package version and Dart SDK version
- The scheme version byte of the blob
- A description of the impact

Do not include vault keys, member private keys, or item plaintext.
