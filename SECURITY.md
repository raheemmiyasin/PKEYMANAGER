# Security Policy

PKEY MANAGER works directly with your SSH keys, so security reports are taken seriously.

## Supported versions

Only the latest release (and `main`) receive fixes.

## Reporting a vulnerability

**Please do not open a public issue.** Instead, report it privately through
[GitHub Security Advisories](https://github.com/raheemmiyasin/PKEYMANAGER/security/advisories/new).

Include what you found, how to reproduce it, and the impact you expect. You
should get an acknowledgement within a week. Once a fix is released you'll be
credited in the advisory unless you'd rather not be.

## In scope

For example:

- Private key material being read beyond the passphrase header, displayed,
  copied, logged or written anywhere
- Passphrases or passwords passing through the app's own memory or output
- Existing files (keys, `~/.ssh/config`, `authorized_keys`) being overwritten or corrupted
- Command injection through key names, comments, host names or config contents
- Running a binary other than the intended system tool (e.g. `PATH` hijacking of `/usr/bin/ssh-add`)

## Out of scope

Weaknesses in OpenSSH itself, the macOS Keychain, or a machine that's already compromised.
