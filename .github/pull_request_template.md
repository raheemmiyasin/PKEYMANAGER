## What does this change?

<!-- A short description, and the issue it fixes if any (e.g. "Fixes #12"). -->

## How was it tested?

<!-- e.g. `cargo test`, and manually with PKEYMANAGER_SSH_DIR=/tmp/ssh-copy -->

## Checklist

- [ ] `cargo fmt --all` and `cargo clippy --all-targets -- -D warnings` are clean
- [ ] `cargo test` passes
- [ ] README updated if keys, behaviour or requirements changed
- [ ] CHANGELOG.md updated under "Unreleased"
- [ ] The change never reads, displays, copies or deletes private key material
