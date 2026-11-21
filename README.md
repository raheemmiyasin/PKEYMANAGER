# PKEY MANAGER

A terminal UI for the SSH keys in `~/.ssh` on macOS, written in Rust with
[ratatui](https://ratatui.rs) (crossterm backend).

```
 PKEY MANAGER   /Users/you/.ssh  agent: 1 key(s) loaded
┌ Keys (3) ─────────────────────────────────────────────────────────────────┐
│  Name                 Type      Comment            Private     Agent      │
│▶ id_ed25519           ED25519   you@work           ⚠ no pass   ● loaded   │
│  id_ed25519_github    ED25519   github             🔒 yes      —          │
│  id_rsa_old           RSA       old-server         ⚠ no pass   —          │
└───────────────────────────────────────────────────────────────────────────┘
┌ Details ──────────────────────────────────────────────────────────────────┐
│Fingerprint SHA256:n7of5DtTRjteRaJFqqtGJpQkc6IcdDGA3Pi9q4QjU7Y             │
│Private     /Users/you/.ssh/id_ed25519  mode 600                           │
│Passphrase  NO passphrase                                                  │
│Used by                                                                    │
│  ~/.ssh/config  Host github.com                                           │
└───────────────────────────────────────────────────────────────────────────┘
```

## What it does

| Key | Action |
|-----|--------|
| `↑ ↓` / `j k` | Move between keys |
| `Enter` / `v` | Show the full public key |
| `c` | Copy the public key to the clipboard (`pbcopy`) |
| `n` | Generate a new ed25519 key (`ssh-keygen -t ed25519 -a 100`) |
| `a` | Add the key to ssh-agent and save the passphrase in Keychain (`/usr/bin/ssh-add --apple-use-keychain`) |
| `d` | Remove the key from ssh-agent (`ssh-add -d`). Files are not touched |
| `s` | Copy the key to a server's `authorized_keys` (`ssh-copy-id`), optionally saving a `Host` alias |
| `r` | Rescan |
| `?` | Help |
| `q` / `Esc` | Quit |

For each `*.pub` file in `~/.ssh` it shows:

- type, comment and SHA256 fingerprint (same format as `ssh-keygen -lf`)
- whether the private key is next to it, its file mode, and a warning if it is
  readable by others (ssh refuses such keys; the fix is `chmod 600`)
- whether the private key has a passphrase (read from the key header only)
- whether the key is loaded in ssh-agent (`ssh-add -l -E sha256`)
- where it is used: `Host` blocks in `~/.ssh/config` whose `IdentityFile` points
  at it, and lines in `~/.ssh/authorized_keys` that let it log in to this Mac

### Copying a key to a server (`s`)

Select a key, press `s` and fill in:

- **Server**: `user@host` (e.g. `ubuntu@203.0.113.10`) or an existing `Host` name from `~/.ssh/config`
- **Port**: leave blank for 22
- **Save as** (optional): a short name such as `web1`

The app runs `ssh-copy-id -i <key>.pub [-p port] user@host`. You type the
server password once, into ssh itself. ssh-copy-id appends the key to
`~/.ssh/authorized_keys` on the server (never overwriting it) and skips keys
that are already there. If you filled in **Save as**, and only if the copy
succeeded, this block is appended to your `~/.ssh/config`:

```
Host web1
  HostName 203.0.113.10
  User ubuntu
  IdentityFile ~/.ssh/id_ed25519
  IdentitiesOnly yes
```

after which `ssh web1` logs in with that key. Existing config entries are never edited.

`known_hosts` is deliberately not checked: it holds *servers'* host keys, not
your keys, so it never references them.

### Safety

- Private keys are never displayed, copied, moved or deleted. They are opened
  only to read the header that says whether a passphrase is set.
- Passphrases are typed directly into `ssh-keygen` / `ssh-add`. The app leaves
  the TUI, hands over the terminal, and comes back after you press Enter.
- New keys never overwrite an existing file.

## Build and run

Requirements: Rust 1.88 or newer (`rustup update` if older). Install with
`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` or
`brew install rustup && rustup-init`.

```sh
cd ~/CODES/PKEYMANAGER
cargo run                 # debug build and run
cargo test                # unit tests (one test uses ssh-keygen in a temp dir)
cargo build --release     # optimised binary at target/release/pkeymanager
cargo install --path .    # installs `pkeymanager` into ~/.cargo/bin
```

To try it on a copy instead of your real keys:

```sh
cp -Rp ~/.ssh /tmp/ssh-copy
PKEYMANAGER_SSH_DIR=/tmp/ssh-copy cargo run
```

### macOS notes

- `a` uses `/usr/bin/ssh-add` on purpose. Homebrew's `openssh` does not support
  `--apple-use-keychain`, so a Homebrew `ssh-add` earlier in `PATH` would fail.
- Keys added with `--apple-use-keychain` are loaded again after a reboot only if
  `~/.ssh/config` has:

  ```
  Host *
    UseKeychain yes
    AddKeysToAgent yes
    IdentityFile ~/.ssh/id_ed25519
  ```

## Code tour (for learning Rust)

| File | What's in it | Rust ideas worth reading for |
|------|--------------|------------------------------|
| `src/main.rs` | terminal setup, event loop, suspend/resume around `ssh-keygen` | `&mut` borrowing, closures with `FnOnce` trait bounds (like `Supplier<T>`) |
| `src/app.rs` | state and key handling | `Option<&T>`, returning an `Action` enum instead of touching the terminal (keeps the borrow checker happy) |
| `src/keys.rs` | scanning, fingerprints, passphrase detection, config parsing | enums with data, explicit lifetimes in `read_ssh_string`, `let ... else` |
| `src/ssh.rs` | `ssh-add`, `ssh-keygen`, `pbcopy` | `std::process::Command`, scope-based closing of pipes (`Drop`, like try-with-resources) |
| `src/ui.rs` | all drawing | immediate-mode rendering, `Stylize` trait methods (`.green()`, `.bold()`) |

Limits of this version: `Include` lines in `~/.ssh/config` are not followed,
and private keys without a matching `.pub` file are not listed.
