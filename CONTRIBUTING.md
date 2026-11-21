# Contributing to PKEY MANAGER

Thanks for your interest! Bug reports, ideas, docs fixes and code are all welcome.

## Ground rules

This tool sits next to people's SSH keys, so a few rules are non-negotiable:

- **Never read private key material** beyond the header that says whether a
  passphrase is set. Never display, copy, move, or delete private keys.
- **Passphrases and passwords go straight to `ssh-keygen` / `ssh-add` / `ssh`.**
  The app hands over the terminal; it must never see or store them.
- **Don't overwrite user files.** New keys must not replace existing ones, and
  `~/.ssh/config` is only ever appended to.
- No network access other than what the user explicitly starts (`ssh-copy-id`).
- No telemetry.

## Getting started

You need Rust 1.88+ and the OpenSSH tools (`ssh-keygen`, `ssh-add`).

```sh
git clone https://github.com/raheemmiyasin/PKEYMANAGER.git
cd PKEYMANAGER
cargo test
```

Always develop against a **copy** of your keys, not the real thing:

```sh
cp -Rp ~/.ssh /tmp/ssh-copy
PKEYMANAGER_SSH_DIR=/tmp/ssh-copy cargo run
```

The [Code tour](README.md#code-tour-for-learning-rust) in the README explains
what lives in each file.

## Making a change

1. For anything bigger than a small fix, open an issue first so we can agree on
   the approach.
2. Fork the repo and create a branch: `git checkout -b fix/short-description`.
3. Make your change and add a test where practical (see `src/keys.rs` for
   examples, including one that runs `ssh-keygen` in a temp directory).
4. Run the same checks CI runs:

   ```sh
   cargo fmt --all
   cargo clippy --all-targets -- -D warnings
   cargo test
   ```

5. Add a line to `CHANGELOG.md` under **Unreleased**.
6. Open a pull request and fill in the template.

## Style

- `rustfmt` defaults; clippy must be warning-free.
- Comments are welcome. The codebase is written to be readable by people
  learning Rust, so explain non-obvious language features rather than avoiding them.
- Keep dependencies minimal. Discuss new crates in an issue first.

## Reporting bugs

Use the bug report template. **Never paste private keys or passphrases**;
public keys and fingerprints are fine. Security problems go through
[SECURITY.md](SECURITY.md), not public issues.

## License

By contributing you agree that your contributions are licensed under the
[MIT License](LICENSE).
