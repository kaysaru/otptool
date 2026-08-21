# otptool

Small cross-platform CLI that prints the current TOTP code for one configured account.

The first version is configured for this account's TOTP parameters: HMAC-SHA256,
six digits, and a 30-second period.

## Install and use locally

Build an optimized binary:

```sh
cargo build --release
```

The macOS/Linux binary is at `target/release/otptool`; on Windows it is `target/release/otptool.exe`.

Configure the TOTP secret once. Input is hidden and the secret is stored in a local TOML file:

```sh
otptool setup
```

The configuration file is located at:

- Linux: `$XDG_CONFIG_HOME/otptool/otprc`, or `~/.config/otptool/otprc`
- macOS: `~/Library/Application Support/otptool/otprc`
- Windows: `%LOCALAPPDATA%\otptool\otprc`

On macOS and Linux, the tool sets the directory permissions to `0700` and the file permissions to `0600`.

## Commands

```sh
otptool             # code, then seconds until it expires
otptool --code      # only the code; suitable for pipes
otptool --copy      # copy the code and print the normal output
otptool --code --copy
otptool setup
otptool uninstall    # remove the local configuration and TOTP secret
```

Short flags are `-c` for `--code` and `-C` for `--copy`; they can be combined as `-cC`.

`otptool uninstall` asks for confirmation before permanently deleting the local
configuration and secret. Use `otptool uninstall --yes` for non-interactive
cleanup. Because this is a portable application, the command then prints the
exact executable path that should be deleted to finish uninstalling.

## Releases

Pushing a tag such as `v0.1.0` runs the GitHub Actions workflow and publishes standalone binaries for macOS Apple Silicon, Windows x86_64, and Linux x86_64. End users do not need Rust or Cargo.
