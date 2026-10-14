# local-vault-rs

The local vault of the decentralized Bitwarden clients, in one implementation that every client
uses: the Android app (`clyu/bitwarden-android`) and the browser extension (the fork of
`bitwarden/clients`). Both have this repository as a git submodule.

The clients work without a Bitwarden server. What a server would have stored is kept in a vault
folder, and the server is replaced by a local server that answers the same HTTP API from the
files. The design is described in `docs/DECENTRALIZATION.md` of the Android app, and the format
of the vault folder in `docs/LOCAL_VAULT_FORMAT.md` there, which is the contract between clients.

Each client had its own implementation of the local server before, in Kotlin and in TypeScript,
and they drifted apart in details that decide what ends up in `vault.json`. This one replaces
both.

## Crates

| Crate | What it is |
|-------|------------|
| `crates/local-vault` | The local server: its routes and handlers, the vault store, the password verifier and the tokens. It has no dependency on a platform. |
| `crates/local-vault-uniffi` | The library for Kotlin, through [UniFFI](https://mozilla.github.io/uniffi-rs/). |
| `crates/local-vault-wasm` | The module for JavaScript, through [wasm-bindgen](https://rustwasm.github.io/wasm-bindgen/). |
| `crates/uniffi-bindgen` | Generates the Kotlin of `local-vault-uniffi`. |

A client brings three things:

- **The file system of the vault folder**: list, exists, read, write, rename and delete, on paths
  that are lists of names relative to the folder. The operations are asynchronous, as the
  extension reaches the folder through messages to another program. The Android app answers
  right away, and the binding for Kotlin waits for the local server on the thread of the call.
- **The platform**: the time, random bytes (the binding for Kotlin takes those of the operating
  system) and a log.
- **The interception point**: where the requests of the client for a Bitwarden server are
  handed to the local server, and its responses turned into HTTP responses.

The content of attachments does not pass through the local server, so that a client can write
and read it as a stream. A response says where the body of the request has to be stored
(`store_request_body_at`) or names the file whose content is its body (`ResponseBody::File`), and
the client does that with its own file system.

## Where the earlier implementations differed

| What | Android app (Kotlin) | Extension (TypeScript) | Now |
|------|----------------------|------------------------|-----|
| `vault.json` that starts with a byte order mark | Taken for an incomplete file, so an older vault was read from `vault.json.tmp` or `vault.json.bak` | Read | Read |
| An integer, such as `version` or `iterations` | The string `"1"` was one, `1.0` was not | `1.0` was one, the string `"1"` was not | A number that is written as an integer |
| Numbers in fields that a client does not know | Kept as written | Normalized (`1.0` to `1`), and rounded beyond 2^53 | Kept with their digits: `1.0` stays `1.0`, and nothing is rounded. Only an exponent gets its sign, `1e+3` for `1e3` |
| A date without an offset from UTC | Not a date | The local time of the device | Not a date |
| `DELETE ciphers/{id}/attachment/{id}` | Revision date kept, empty response | New revision date, `{cipher}` in the response | Revision date kept, `{cipher}` in the response: the app is not sent the item and keeps the revision date that it knows it by |
| `userKeyId`, `encryptedByKeyId` | Not recorded, not checked | Recorded once, items of another key refused | Recorded once, items of another key refused |
| Routes that only the extension uses (several items at once, `partial`, `move`, `purge`, `folders/all`, `verify-password`, `profile`, `prelogin/password`) | Not there | There | There |
| The ID of an item or a folder in a path | Any segment | A UUID | A UUID |
| `fileSize` of an attachment, and its `sizeName` | Negative sizes kept; rounded half up | Negative sizes taken as 0; rounded by `toFixed` | Negative sizes taken as 0; rounded half up |
| The master password hint | `429`, the only status whose message the app shows | `400`, as the extension shows a message of its own for `429` | By client (`ClientKind`), the only thing that differs |
| Claims of the access token | Without `client_id` | With `client_id` | With `client_id` |
| A refused request in the log | IDs as `*` | Anything but words of the API as `{}` | Anything but words of the API as `*` |

## Building and testing

GitHub Actions does it all, in `.github/workflows/ci.yml`:

- `cargo fmt`, `cargo clippy` with every warning an error, and `cargo test`. The tests of the
  local server are in `crates/local-vault/tests`, and include a vault that the Android app wrote
  (`tests/fixtures/android-vault.json`).
- The module for JavaScript, tested in Node with `wasm-pack test --node`, and built for webpack
  and for Node.
- The libraries for every ABI of Android with `cargo ndk`, and their Kotlin.

The same, by hand:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

rustup target add wasm32-unknown-unknown
wasm-pack test --node crates/local-vault-wasm
wasm-pack build crates/local-vault-wasm --release --target bundler --out-dir ../../pkg/bundler

rustup target add aarch64-linux-android
cargo ndk -t arm64-v8a -o jniLibs build --release -p local-vault-uniffi
cargo build --release -p local-vault-uniffi
cargo run --release -p uniffi-bindgen -- generate --no-format \
    --library target/release/liblocal_vault_uniffi.so --language kotlin --out-dir kotlin
```

When the formatting check fails, the run has the change that `cargo fmt` makes as the artifact
`rustfmt-patch`: `git apply rustfmt.patch` applies it.

## License

GPL-3.0, as the clients that it was ported from.
