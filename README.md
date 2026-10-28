# local-vault-rs

The local vault of the decentralized Bitwarden clients, in one implementation that every client
uses: the Android app (`clyu/bitwarden-android`) and the browser extension (the fork of
`bitwarden/clients`). Both have this repository as a git submodule.

The clients work without a Bitwarden server. What a server would have stored is kept in a vault
folder, and the server is replaced by a local server that answers the same HTTP API from the
files. The design is described in [docs/DESIGN.md](docs/DESIGN.md), and the format of the vault
folder in [docs/LOCAL_VAULT_FORMAT.md](docs/LOCAL_VAULT_FORMAT.md), which is the contract between
clients.

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

A client brings five things:

- **The file system of the vault folder**: list, exists, read, write, rename and delete, on paths
  that are lists of names relative to the folder. The operations are asynchronous, as the
  extension reaches the folder through messages to another program. The Android app answers
  right away, and the binding for Kotlin waits for the local server on the thread of the call.
- **The platform**: the time, random bytes (the binding for Kotlin takes those of the operating
  system) and a log.
- **The interception point**: where the requests of the client for the host `vault.local.invalid`
  are handed to the local server as they are (method, address, headers, body), and its responses,
  which say their media type, turned into those of the HTTP client.
- **The ID of its installation**, which is the same every time it starts. Every device writes its
  changes to a directory of the vault folder named after it, which no other device writes, so
  that a tool that syncs the folder never has two versions of a file to choose from, and the
  vault is put together from the files of every device. It is made of 1 to 128 ASCII letters,
  digits, `-` and `_`, as a UUID is: no local server is created for any other ID.
- **The name and the type of its device**, as it names them to a Bitwarden server when it logs in
  (`deviceName` and `deviceType`): the model of the phone and `0` for the Android app, and the
  browser, such as `chrome`, and the type of the extension in it, such as `2`, for the extension.
  The files of the device say them, so that the user can tell the devices that share the vault
  folder apart.

What a request asks for is worked out here, once for every client: the service it is for, the
account of its token, its form and its query. The content of attachments is either streamed by
the client, which leaves it out of the request and stores it where the response says
(`handle_http`, as the Android app does), or handed over whole and stored by the local server
under the lock of the request (`handle_http_buffered`, as the extension does).

What a client copies when the vault moves to another folder is worked out here too: the accounts
that the other folder does not have (`accounts_missing_in`), and of those that it has, the files
of the device and the content of attachments that it does not have yet
(`device_files_missing_in`). A client calls them, copies what they give in the order that they
give it in, and does only the copying itself, as a stream.

Which devices have a file in the vault of an account, and retiring one that is gone for good, which
another device then takes the file of over and whose directory is deleted 90 days later, are
requests of their own, which a Bitwarden server does not have: `GET local-vault/devices` and
`POST local-vault/devices/{id}/retire`. A client makes them as any other request, and only shows
what they answer: each device by its name and its type, if its file says them, and when it last
changed the vault.

The rules that a client checks itself against are here as well, so that its tests do not hold a
copy of them:

| Rule | What a client checks with it |
|------|------------------------------|
| `is_answered` | Every request that its code can make: answered, or refused as needing a server. |
| `FLAGS_THAT_MUST_BE_OFF` | Its feature flags that move requests out of reach of the local server: still there, and off by default. |
| `check_file_system` | Its file system keeps the rules that the vault store counts on. |

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
| What a request is | The path relative to the service, as OkHttp has it before the address of the server is filled in; a form by the type of the body | The address without `api`, `identity` or `events`; a form by `Content-Type`; segments that do not decode taken as they are | The address, without `api`, `identity` or `events`; a form by `Content-Type`; segments that do not decode taken as they are |
| An account directory, to copy to another folder | `[A-Za-z0-9_-]{1,128}` in the app | Not copied | `is_safe_segment` |

## Building and testing

GitHub Actions does it all, in `.github/workflows/ci.yml`:

- `cargo fmt`, `cargo clippy` with every warning an error, and `cargo test`. The tests of the
  local server are in `crates/local-vault/tests`, and include a vault that the Android app wrote,
  in the file of the device that took it over (`tests/fixtures/android-vault.json`).
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

Each client builds the local vault itself, from the submodule that it has it in: the Android app
in `network/build.gradle.kts`, and the extension with
`apps/browser/src/local-vault/build-local-vault.sh`.

## License

GPL-3.0, as the clients that it was ported from.
