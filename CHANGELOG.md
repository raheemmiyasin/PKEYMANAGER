# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Open-source project files: LICENSE, CONTRIBUTING, CONTRIBUTORS, SECURITY, CODE_OF_CONDUCT,
  issue/PR templates, CI and Dependabot.

## [0.1.0]

### Added

- Terminal UI listing every `*.pub` key in `~/.ssh` with its type, comment,
  SHA256 fingerprint, private key file mode, passphrase status and ssh-agent status.
- Shows where each key is used in `~/.ssh/config` and `~/.ssh/authorized_keys`.
- Generate ed25519 keys, add/remove keys in ssh-agent with Keychain support,
  copy public keys to the clipboard, and copy keys to servers with `ssh-copy-id`.

[Unreleased]: https://github.com/raheemmiyasin/PKEYMANAGER/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/raheemmiyasin/PKEYMANAGER/releases/tag/v0.1.0
