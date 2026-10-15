# Local vault format

The decentralized Bitwarden clients do not talk to a Bitwarden server. What the server would have
stored is kept on the device instead, in files that any other app can read and write as long as it
keeps to this document. It is written for whoever makes another client, such as a desktop app,
share a vault with them.

Nothing in these files is more readable than it is on a server: every secret is encrypted by the
Bitwarden SDK before it gets here, with keys that can only be unlocked with the master password.

The clients do not each implement what follows: they share one implementation, the local vault in
Rust in this repository, which each of them has as a submodule. A client that is not built on it
has to keep to this document all the same. How the local vault is built and what a client brings
to it is in [DESIGN.md](DESIGN.md).

## Where the vault is kept

The vault lives in the folder that the user chooses for it:

- The Android app: under **Settings › Other › Vault folder**. Until a folder is chosen it lives in
  the storage of the app, at `Android/data/<application id>/files/vault/`.
- The browser extension: the folder that is given when its helper is installed, which reads and
  writes the files for it (`apps/browser/native-host/README.md` of the extension).

Every account has a directory of its own, named after the ID of the account:

```
<vault folder>/
└── <account id>/
    ├── vault.json
    ├── vault.json.bak
    └── attachments/
        └── <cipher id>/
            └── <attachment id>
```

| File | Content |
|------|---------|
| `vault.json` | The account and everything in its vault. |
| `vault.json.bak` | The `vault.json` from before the last change. |
| `vault.json.tmp` | Only exists while `vault.json` is being replaced. |
| `attachments/<cipher id>/<attachment id>` | The content of an attachment, exactly as the SDK encrypted it. |

IDs are UUIDs. A name that is not made of letters, digits, `-` and `_` only is never used as the
name of a file or a directory.

IDs are compared without regard to case, but each is written in one way only: the way that
`vault.json` has it. `<cipher id>` and `<attachment id>` in the path of an attachment are the
`id` of the item and of the attachment exactly as `vault.json` has them, and changing an item or
a folder never changes its `id`. A client that is asked for an ID in another case looks it up in
the vault first and goes by what it finds there, as a file is not found under a name in another
case wherever a file system tells the two apart.

A file under `attachments` that no item lists is left over from an attachment whose file could
not be deleted when it was removed from the vault. Nothing reads it.

## vault.json

```jsonc
{
  "format": "bitwarden-local-vault",
  "version": 1,
  "revisionDate": "2026-10-11T12:00:00.000Z",
  "account": {
    "masterPasswordVerifier": {
      "algorithm": "PBKDF2-SHA256",
      "iterations": 100000,
      "salt": "<base64>",
      "hash": "<base64>"
    }
  },
  "sync": { /* the body of the Bitwarden API response to GET /sync */ }
}
```

| Field | Meaning |
|-------|---------|
| `format` | Always `bitwarden-local-vault`. A file with another value is not a vault. |
| `version` | The version of this layout. A file with a version that a client does not know must be left alone. |
| `revisionDate` | When the file was last written, as an ISO-8601 date in UTC. |
| `account` | What a server keeps to itself about the account. |
| `sync` | The vault, in the shape that every Bitwarden client already reads. |

A file is UTF-8 encoded JSON. The order of the fields carries no meaning, and fields that a client
does not know must be kept when the file is written back. How the JSON is read and written:

- A byte order mark at the start of a file is left out, and bytes that are not UTF-8 are read as
  U+FFFD. A file is complete if what remains is a JSON document.
- An integer, such as `version`, the `kdf` parameters or `iterations`, is a number written as an
  integer: `1` is one, but `1.0`, `1e0` and the string `"1"` are not.
- A number in a field that a client does not know is written back with the digits that it was read
  with: `1.0` stays `1.0`, and an integer beyond 2^53 is not rounded. An exponent may be written
  with its sign, `1e+3` for `1e3`.
- A date is an ISO-8601 date and time with an offset from UTC, such as `2026-10-11T12:00:00.000Z`
  or `2026-10-11T14:00+02:00`. Anything else is not a date, among it one without an offset, which
  would mean another time on every device. Dates are written in UTC with milliseconds.

### sync

`sync` is exactly what the Bitwarden server returns for `GET /sync`, so the code that a client
already has for reading that response reads a vault as well. The parts of it that are in use:

| Field | Content |
|-------|---------|
| `profile` | The account: `id`, `email`, `name`, `masterPasswordHint`, `securityStamp`, `creationDate`, the user key encrypted with the master key in `key`, and the encrypted private key in `privateKey` and `accountKeys`. |
| `userDecryption.masterPasswordUnlock` | How the vault is unlocked: the `salt` and the `kdf` parameters (`kdfType`, `iterations`, `memory`, `parallelism`) that the master key is derived with, and `masterKeyEncryptedUserKey`. |
| `userDecryption.userKeyId` | The ID of the user key, once a client had it recorded (the Bitwarden SDK of the browser extension does). It is recorded once, and never replaced by the ID of another key. |
| `folders` | The folders: `id`, encrypted `name`, `revisionDate`. |
| `ciphers` | The items, each as the server returns a cipher. `attachments` lists the `id`, `fileName`, `key`, `size` and `sizeName` of the attachments, the content of which is in the `attachments` directory. What a client sends about the request and not about the item (`lastKnownRevisionDate`, `attachments2`, `encryptedFor`, `encryptedByKeyId`) is not part of an item. An item that an earlier build stored can still have `encryptedFor`, which nothing reads. |
| `sends`, `collections`, `policies`, `domains` | Always empty: these are about sharing with other people, which needs a server. |

An account is always reported as premium, as there is no server to buy a subscription from.

### account.masterPasswordVerifier

A client never stores or sends the master password. To log in it derives a hash from it, the way
it does for a server (`HashPurpose.SERVER_AUTHORIZATION` in the SDK), and that hash is checked
against the verifier:

```
hash = PBKDF2-HMAC-SHA256(
    password   = the hash of the client, as the ASCII bytes of its Base64 text,
    salt       = salt,
    iterations = iterations,
    length     = 32 bytes,
)
```

The password is the right one if the result equals `hash`. This is the counterpart of the hash
that a server stores for the same purpose. It does not make the master password easier to guess
than the encrypted user key in `sync` already does, since deriving the hash of the client costs
at least as much as deriving the master key.

## Accounts with the same email address

The account that an email address belongs to is the one whose `sync.profile.email` is that
address, compared without regard to case and to the whitespace around it. Nothing keeps a vault
folder from holding more than one such account: an address that is registered again on a device
that the first account has not arrived on yet makes a second one, and so does putting the account
directories of two folders together.

Every client has to deal with them in the same way, or two devices open different vaults for the
same address:

- The accounts with the address are taken in the order of their IDs, which are the names of
  their directories, compared as strings by their UTF-16 code units. That is the order that
  strings are sorted in by default in Kotlin, Java and JavaScript. The order that a directory
  is listed in is not to be relied on.
- Logging in goes through the accounts in that order and takes the first one whose
  `masterPasswordVerifier` the password is right for.
- Where there is no password to go by, the first account is the one that is meant: for the KDF
  parameters that a client asks for before it logs in, for the master password hint, and for
  whether an address is taken when it is registered.

An account other than the first one can therefore only be logged in to with a master password
that no account before it has, and if its master key is derived with the same KDF parameters as
that of the first one.

## Changing a vault

A client that changes a vault has to:

1. Read `vault.json`. If it is missing or not complete JSON, read `vault.json.tmp` instead, and
   `vault.json.bak` if that one is no good either. Only an interrupted write leaves the vault in
   anything but `vault.json`. The first of these files that is complete is the vault, also when
   it has a `format` or a `version` that the client does not know: the client then has no vault
   to change, and must not go on to the next file, which holds an older vault.
2. Make the change in `sync`, in the form the server would return it: a new item gets an `id`, a
   `creationDate` and a `revisionDate`; a changed item gets a new `revisionDate`.
3. Set the top level `revisionDate` to the current time.
4. Write the result to `vault.json.tmp`, delete `vault.json.bak`, rename `vault.json` to
   `vault.json.bak`, and rename `vault.json.tmp` to `vault.json`.

An item is only replaced if its `revisionDate` in the file is the one that the client last saw,
give or take a second. Otherwise somebody else changed it in the meantime, and the client has to
read the vault again first.

An item is only stored in the vault of the account that it was encrypted for. The Bitwarden API
has a client say which account that is, in `encryptedFor`, and an item that names another account
than the one whose vault is changed must be refused: it could not be decrypted there, and as an
update it would replace an item that can. The same goes for the key that it was encrypted with: an
item whose `encryptedByKeyId` is not the `userKeyId` of the vault is refused. Where either of the
two is missing, there is nothing to tell by.

The revision date that a client knows an item by is the one that it was last sent. So a change
that a client may not be sent the item for keeps the revision date of the item: moving an item to
the trash, moving it to a folder, and removing an attachment, which the Android app is not sent
the item for and the browser extension is.

An attachment or an item is removed from `vault.json` before the files of its attachments are
deleted, so that the vault never lists an attachment whose content is gone.

Changing the master password replaces `account.masterPasswordVerifier`, `profile.key` and
`userDecryption.masterPasswordUnlock`, and sets `profile.securityStamp` to a new UUID. A client
that sees the security stamp of an account change has to log the account out, as its copy of the
user key is unlocked with the old password.

## Sharing a vault between devices

The vault folder can be shared with whatever moves files between devices, such as Syncthing. A
client notices that `vault.json` was replaced the next time it syncs, by comparing `sync` with
what it last read, and then takes over everything that is in it.

The whole vault is one file, so if it is changed on two devices before they exchange it, one of
the two versions wins and the changes in the other are not in it. A tool that keeps the losing
version, as Syncthing does under a name with `sync-conflict` in it, leaves it next to the vault,
where nothing reads it.
