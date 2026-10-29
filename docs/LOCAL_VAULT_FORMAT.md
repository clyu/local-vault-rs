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

Every account has a directory of its own, named after the ID of the account. Every device that
shares the vault folder writes a file of its own in it, which no other device writes, so that a
tool that syncs the folder never has two versions of one file to choose from:

```
<vault folder>/
└── <account id>/
    ├── vault.json
    ├── devices/
    │   └── <device id>/
    │       ├── vault.json
    │       └── vault.json.bak
    └── attachments/
        └── <cipher id>/
            └── <attachment id>
```

| File | Content |
|------|---------|
| `vault.json` | Only which layout the directory has, or that the account was deleted. |
| `devices/<device id>/vault.json` | What the device wrote of the vault: see [The file of a device](#the-file-of-a-device). |
| `devices/<device id>/vault.json.bak` | That file from before the last change. |
| `devices/<device id>/vault.json.tmp` | Only exists while that file is being replaced. |
| `attachments/<cipher id>/<attachment id>` | The content of an attachment, exactly as the SDK encrypted it. |

The ID of a device is that of the installation of the client, which is the same every time that
it starts and is never the one of another installation: the UUID that the Android app identifies
itself to a Bitwarden server with, and one that the browser extension keeps for the local vault.
The directory of a device must not be deleted by hand: part of the vault may be in no other file.
A device that is gone for good is retired instead, which deletes its directory once nothing is lost
with it (see [Retiring a device](#retiring-a-device)).

IDs are UUIDs. A name that is not made of letters, digits, `-` and `_` only is never used as the
name of a file or a directory.

IDs are compared without regard to case, but each is written in one way only: the way that the
vault has it. `<cipher id>` and `<attachment id>` in the path of an attachment are the `id` of the
item and of the attachment exactly as the vault has them, and changing an item or a folder never
changes its `id`. A client that is asked for an ID in another case looks it up in the vault first
and goes by what it finds there, as a file is not found under a name in another case wherever a
file system tells the two apart.

A file under `attachments` that no item lists is left over from an attachment whose file could
not be deleted when it was removed from the vault. Nothing reads it.

## vault.json

The `vault.json` of an account only says that its directory has this layout:

```json
{
    "format": "bitwarden-local-vault",
    "version": 2
}
```

In version 1 of this layout, this file held the whole vault (see
[The earlier layout](#the-earlier-layout)). The file is written by the device that the account
first has a file of, which is the one that registers the account (see
[Changing a vault](#changing-a-vault)). Every device writes the same content, so two devices that
write it at once write the same file.

The `vault.json` of an account that was deleted only says that:

```json
{
    "format": "bitwarden-local-vault-deleted"
}
```

The account is then not there, whatever else its directory has (see
[Deleting an account](#deleting-an-account)). This is not a vault, so a client that does not know
it takes it for a layout that it does not know, which it does not use or write.

## The file of a device

```jsonc
{
  "format": "bitwarden-local-vault",
  "version": 2,
  "revisionDate": "2026-10-11T12:00:00.000Z",
  "account": {
    "masterPasswordVerifier": {
      "algorithm": "PBKDF2-SHA256",
      "iterations": 100000,
      "salt": "<base64>",
      "hash": "<base64>"
    }
  },
  "sync": { /* the body of the Bitwarden API response to GET /sync, as far as the device holds it */ },
  "records": {
    "account": {"at": 1791720000000, "by": "<device id>", "in": 1791720000000},
    "masterPassword": {"at": 1791720000000, "by": "<device id>", "in": 1791720000000},
    "cipher:<id>": {"at": 1791720000000, "by": "<device id>", "in": 1791720000000}
  },
  "tombstones": {
    "folder:<id>": {"at": 1791720000000, "by": "<device id>", "in": 1791720000000}
  },
  "removedAttachments": {
    "<cipher id>/<attachment id>": 1791720000000
  },
  "device": {"id": "<device id>", "name": "Pixel 8", "type": 0}
}
```

| Field | Meaning |
|-------|---------|
| `format` | Always `bitwarden-local-vault`. A file with another value is not a vault. |
| `version` | The version of this layout, `2`, or `3` for the file of a device that retired another one: see [Retiring a device](#retiring-a-device). A file with a version that a client does not know must be left alone. |
| `revisionDate` | When the device last changed the vault, as an ISO-8601 date in UTC. |
| `since` | Earlier clients wrote when the device first wrote the file. Nothing reads it, and it is left out when the file is written again. |
| `account` | What a server keeps to itself about the account. |
| `sync` | The vault, in the shape that every Bitwarden client already reads, as far as the device holds it. |
| `records` | The stamp of every record that the file holds. |
| `tombstones` | The stamp of every deletion that the file holds. |
| `removedAttachments` | The attachments that the device removed from the vault and has yet to delete the content of, by the IDs of the item and of the attachment as the vault had them, with when it removed them, in milliseconds since the epoch: see [The content of attachments](#the-content-of-attachments). A file without it has none. |
| `retiredDevices` | The devices that the device retired, by their IDs: when it retired each of them, in milliseconds since the epoch (`at`), and the `revisionDate` of the file of that device that it took over (`revisionDate`), as in `{"<device id>": {"at": 1791720000000, "revisionDate": "2026-10-11T12:00:00.000Z"}}`. Only a file of version 3 has it: see [Retiring a device](#retiring-a-device). |
| `device` | What the device is, as its client names it to a Bitwarden server when it logs in, so that the user can tell the devices that share the vault folder apart: the ID of the device (`id`), its `name`, such as the model of a phone or the browser that an extension is in, and its `type`, the number of its kind of device in the Bitwarden API (`DeviceType`), such as `0` for Android and `2` for an extension in Chrome. A file whose `device` has another `id`, or no `name` or `type`, does not say what its device is: a client that does not know the field takes it for part of the record of the account, and writes it in its own file with a change of the account, as it came in the file of another device. Nor does a file without it, as earlier clients wrote. |

### Records and stamps

The vault is made of records: the record of the master password, the record of the account, every
folder and every item.

The record of the master password is these fields, at their places in the file:
`account.masterPasswordVerifier`, `sync.profile.key`, `sync.profile.masterPasswordHint`,
`sync.profile.securityStamp` and `sync.userDecryption.masterPasswordUnlock`. It is changed as a
whole: the verifier, the user key encrypted with the master key, the parameters that the master
key is derived with and the security stamp are never taken from two different versions. The
record of the account is everything else in the file but `sync.folders`, `sync.ciphers` and the
fields that are about the file (`format`, `version`, `revisionDate`, `since`, `records`,
`tombstones`, `removedAttachments`, `retiredDevices` and `device`). The two are records of their
own, so that a change of the account that a device makes before the newest master password has come
to it, such as recording the ID of the user key, does not bring an older master password back. A
folder and an item are records of their own. A record has a key: `masterPassword`, `account`,
`folder:<id>` or `cipher:<id>`, with the ID in lower case.

A file holds the versions of the records that its device wrote and that it does not leave to
another device yet, and the deletions of other devices that it put in place of such versions (see
[What a device no longer has to hold](#what-a-device-no-longer-has-to-hold)). The record of the
account is only in it if `records` has a stamp for `account`, and that of the master password if
`records` has a stamp for `masterPassword`. The folders and the items are in `sync.folders` and
`sync.ciphers`. A deletion holds no record, only its stamp in `tombstones`.

A stamp says when a version was written, in milliseconds since the epoch (`at`), and by which
device (`by`). Of two versions of a record, the one with the later `at` is the newer one, and of
two with the same `at`, the one whose `by` comes later, compared as strings by their UTF-16 code
units. A folder or an item in `sync` that `records` has no stamp for is taken to have been written
at its `revisionDate`, or else at the `revisionDate` of the file, by no device (`""`).

A stamp in the file of a device also says when the version came into that file (`in`): the
`revisionDate` that the file had when the device first wrote it with the version, in milliseconds
since the epoch. It is about the file, and not the version: a device that takes a version over from
another file gives it the `revisionDate` of its own. It tells what a file holds since a file of its
device that another device took over from what came into it later (see
[Retiring a device](#retiring-a-device)). Earlier clients did not write it, and a stamp without it
is kept without it.

### JSON

A file is UTF-8 encoded JSON. The order of the fields carries no meaning, and fields that a client
does not know must be kept when the file is written back. How the JSON is read and written:

- A byte order mark at the start of a file is left out, and bytes that are not UTF-8 are read as
  U+FFFD. A file is complete if what remains is a JSON document.
- An integer, such as `version`, `at`, the `kdf` parameters or `iterations`, is a number
  written as an integer: `1` is one, but `1.0`, `1e0` and the string `"1"` are not.
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

An account is never in an organization. Whatever a file says about organizations is not handed to
a client, as whoever can write to the vault folder could otherwise put the account in one of their
own: `collections`, `policies` and `policiesNew` are returned empty, and so are `organizations`,
`organizationsNew`, `providers` and `providerOrganizations` of `profile`, its `usesKeyConnector`
and `forcePasswordReset` are `false`, and the `organizationId` of an item is `null` and its
`collectionIds` empty. Each of them is replaced in whatever case its key is written in, if a file
has it, as a client may read a field by another case. The file itself is left as it is.

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

## Putting the vault together

The vault of an account is put together from all of its files, the same way on every device:

1. Read `vault.json` of the account, or `vault.json.tmp` if it is missing or not complete JSON,
   but not `vault.json.bak`, which can hold a vault of the earlier layout (see
   [The earlier layout](#the-earlier-layout)). One of version 2 only says that the account has
   this layout. One that says that the account was deleted means that the account is not there,
   and nothing else of it is read.
2. Read the file of every device, which is `vault.json` of the directory of the device, or
   `vault.json.tmp` if it is missing or not complete JSON, and `vault.json.bak` if that one is no
   good either, in the order of the IDs of the devices, compared as strings by their UTF-16 code
   units. The order that a directory is listed in is not to be relied on. A directory without a
   complete file is skipped.
3. If the first complete file of `vault.json` of the account or of a device has a `format` or a
   `version` that the client does not know, the client has no vault to use or to change, and
   must not go on to the next file of that directory, which holds an older one: a newer client
   wrote it. It must not take the account to be gone either, but treat it as an account whose
   files are on their way (see below) until the client is updated. A `vault.json` of the account
   of version 1 is treated the same way, as no device took it over (see
   [The earlier layout](#the-earlier-layout)). Only a `vault.json` of the account whose `format`
   is not `bitwarden-local-vault`, such as the one that says that the account was deleted, means
   that there is no account.
4. Leave out the file of every device that was retired: one that a note in `retiredDevices` of one
   of the files, a file that is left out included, says was taken over, as the `revisionDate` of
   the file is the one that the note has, or earlier (see [Retiring a device](#retiring-a-device)).
   The device that took it over holds what it held, so the vault is the same without it. A file
   that is left out has still come, for what follows. Of the file of a device that a note in a
   file that is not left out is about, and that is not left out itself, leave out the versions that
   it holds since the file that the latest such note is about: the device that took that file over
   holds them, or what replaced them.
5. Take the newest version of each record, and of versions that are as new, the first one that
   was read. A record whose newest version is a deletion is not in the vault.
6. The vault is the record of the account, with the fields of the record of the master password
   in their places, the folders in `sync.folders` and the items in `sync.ciphers` in the order
   that they were first read in. An account without a record of the account, or without one of
   its master password, is on its way if its `vault.json` says that it has this layout, or if the
   file of a device has come: the file that holds the record has not come yet (see below).
   Otherwise the account is not there.
7. An item whose `folderId` names a folder that was deleted is in no folder, as one device can
   delete a folder while another one puts an item in it. For the same reason, deleting a folder
   leaves the items in it as they are: as new versions of them, it would replace a change of one
   of them that another device made before the deletion came to it.
8. The `revisionDate` of the vault is the latest of those of the files that are not left out.

Every device that has the same files comes to the same vault.

A tool that syncs the folder does not bring the files of an account all at once, nor in the order
that they were written. The `vault.json` of an account can come before the file of the device
that registered the account, and the file of a device that left the master password out (see
[What a device no longer has to hold](#what-a-device-no-longer-has-to-hold)) before the file of
the device that holds the newer one, and the files of the devices before the `vault.json` of the
account. A device that has the `vault.json` of this layout, or the file of a device, but no file
with the record of the account, or none with that of its master password, has no vault to use
until that file comes. It must not take
the account to be gone, as a client logs out an account that it is told is not there: it fails
the requests for the account as ones that did not reach the server. Its email is not known
until then, so a request that looks for an account by an email that no other account has fails
the same way, as the email may be its: the KDF parameters that a client asks for before it logs
in, logging in, the master password hint, and whether an address is taken when it is
registered. Answering that no account has the email would have the client derive the master key
the default way, take the master password to be wrong, or register the address again.

## Changing a vault

A client that changes a vault writes the file of its own device, and no other:

1. Put the vault together, and make the change in it, in the form the server would return it:
   a new item gets an `id`, a `creationDate` and a `revisionDate`; a changed item gets a new
   `revisionDate`.
2. Find the records that the change added, changed or removed, by comparing the vault before
   and after it, and give each a new version: the record, or a deletion for one that is gone.
   Its stamp has the ID of the device, and the current time or one millisecond after the stamp
   of the version that it replaces, whichever is later. A change that is made after another one
   is thus newer than that one, even where the clock of its device is behind.
3. Read the files of the devices again, as the file of another device may have come in since.
   The new file of the device is the versions that it holds, with the new ones in place of those
   of the same records, without what it no longer has to hold (see below), and with
   `revisionDate` set to the current time, or to one millisecond after the `revisionDate` of the
   file that it replaces, or after the latest `revisionDate` that a note about the device in
   `retiredDevices` of one of the files has, whichever is latest: each file that a device writes
   with a change is later than every one before it, which a note that a file was taken over goes
   by (see [Retiring a device](#retiring-a-device)). The stamp of every version that it did not
   hold with the same stamp before has that `revisionDate` as `in`, and the others keep theirs.
   Its `removedAttachments` are those of the file that it
   replaces, with every attachment that the change took out of the vault added at the current
   time: one that an item no longer has, and those of an item that was deleted. Its
   `retiredDevices` are those of the file that it replaces, and its `device` says what the device
   is now.
4. Write the new file to `vault.json.tmp` of the directory of the device, delete
   `vault.json.bak`, rename `vault.json` to `vault.json.bak`, and rename `vault.json.tmp` to
   `vault.json`.
5. If `vault.json` of the account does not say that it has this layout yet, write it the same
   way, but only if no other device has a file of the account, as when the device registers the
   account: the file of the device then holds the records of the account. Otherwise that
   `vault.json` is on its way to the device, from the device that the account first had a file
   of, if that one could write it. Written by the device, it could be written as the account is
   deleted, and a tool that syncs the folder could keep it in place of the `vault.json` that says
   that the account was deleted, and delete the file with the records of the account all the
   same: the account would be taken to be on its way for good. A `vault.json` that cannot be
   written does not undo the change, which is in the file of the device by then. The next change
   writes it, unless another device has a file of the account by then, as when the device that
   registered the account could not write it and another device changed the vault before it
   changed it again: no device writes it then. The account is used all the same, as the files of
   its devices hold its records, but a device that has none of those files yet takes the account
   to be not there, as it does before any file of the account has come, rather than on its way
   (see [Putting the vault together](#putting-the-vault-together)).

An item is only replaced if its `revisionDate` in the vault is the one that the client last saw,
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
the item for and the browser extension is. This is why the `revisionDate` of an item is not its
stamp.

Changing the master password replaces `account.masterPasswordVerifier`, `profile.key`,
`profile.masterPasswordHint` and `userDecryption.masterPasswordUnlock`, and sets
`profile.securityStamp` to a new UUID: it is a new version of the record of the master password.
A client that sees the security stamp of an account change has to log the account out, as its
copy of the user key is unlocked with the old password.

### The content of attachments

The content of an attachment is a file under `attachments`, which every device shares, and not
a version: removing an attachment from the vault does not delete it. A device that had not seen
the removal yet can change the item, or change it after another device deleted it, in a version
that is newer, and that has the attachment again. A device that removes an attachment, or
deletes an item with attachments, notes them in `removedAttachments` of its file instead (see
[Changing a vault](#changing-a-vault)), and only deletes the content when nothing can bring the
attachment back anymore. Purging the vault removes the items that the device has in its vault,
and notes only their attachments: an item that another device added, and whose file has not come
yet, stays in the vault, and keeps the content of its attachments.

When the device looks at what it no longer has to hold (see below), it goes through the
attachments in `removedAttachments`:

- If the item in the vault has the attachment again, a change won over the removal: the
  attachment is left out of `removedAttachments`, and its content is not deleted. The device
  that removes it next notes it.
- Otherwise, if the attachment was removed 90 days ago or more, which is the time that the
  version that has it again can take to come, the content is deleted, and the attachment is
  left out of `removedAttachments` once nothing remains of it. If the vault does not have the
  item, the directory of the item under `attachments` is deleted as well once it is empty. That
  of an item that the vault has is left, as the content of a new attachment of the item can be
  on its way to it.
- Otherwise it stays in `removedAttachments`.

The content of an attachment that the vault does not have is not handed out to a client, even
while it is still there.

### What a device no longer has to hold

A file can take up to 90 days to come to every device that shares the folder, as a device can be
off for a while, so a version has come to every device once its `at` is 90 days old or older. A
device leaves out of its file, when it writes it:

- A version of a record that the file of another device has a newer version of, once that one
  has come to every device. If the newer one is a version of the record of the master password,
  it does so right away: see below.
- A deletion that is 90 days old or older, if no file of another device has the record in a
  version with an earlier stamp, which forgetting the deletion would bring back. The 90 days are
  for a file with such a version that is still on its way: if it comes after the deletion is
  forgotten, the record is back. The deletion of a folder is kept as well while a file, its own
  included, has an item whose `folderId` is that folder, as the item is in no folder only as long
  as the deletion is there.

In place of a version of a record that the file of another device has a newer deletion of, a
device puts that deletion in its file when it writes it, with the stamp that it has there, unless
it leaves the version out as above. Of the deletions of several devices, it puts the newest one
(see below).

A device that does not change the vault looks for these at most once a day, when its client
syncs, and again at the next sync if it could not, along with the content of the attachments
that it removed (see
[The content of attachments](#the-content-of-attachments)) and the directories of the devices
that were retired long enough ago (see [Retiring a device](#retiring-a-device)), and writes its
file if it finds any, if it was retired itself, or if its file does not say what the device is now,
as one that an earlier client wrote does not: a device that only reads the vault would otherwise
never say so. The vault stays the same.

Only the device that a file belongs to leaves anything out of it. A version that a device holds
is therefore in the file of another device before it leaves that file, unless the directory of
that other device is deleted, which is why that must not be done by hand: only the directory of a
device that was retired is deleted, once another device took its file over and every device has
had time to learn it (see [Retiring a device](#retiring-a-device)). A third device can get
the file without the version before the file with the newer one, as a tool that syncs the folder
brings them in no particular order. The 90 days are for that: by then, the newer one has come to
every device, and a device that gets the file without the version still has the record, as it
was before the change or as it is now. Two versions are not held that long nonetheless:

- One that a deletion replaced, which the device replaces with that deletion right away: the
  record is not in the vault either way, and is no longer in the file. The version is not left
  out, as the device that deleted the record put the deletion in place of the version that it
  held. A device that gets this file before the one with the deletion can still have the file of
  that device from before, with that older version, which it would take for the record, and a
  change of it there would bring the record back, older than it was. With the deletion in both
  files, it has the deletion either way.
- One of the record of the master password, which is left out right away, even where the file of
  another device has an older version of it. Its older versions hold what a change of the master
  password replaced, which is not kept longer than it has to be. A device that does not have the
  newer one yet has no vault to use until it comes (see
  [Putting the vault together](#putting-the-vault-together)), or takes an older one that another
  file still has, such as that of a device that is gone for good and was not retired, for the
  master password until then. An older version of the record of the account holds nothing of the
  kind, and is left out as any other one.

## Retiring a device

A device that is gone for good, such as a browser extension that was installed again, and writes
the directory of another ID since, never leaves anything out of its file again. As long as the file
is there, the deletions of the records that it holds older versions of are kept, as is that of a
folder that it has an item in, the content of the attachments that it removed is never deleted,
and the file keeps the master password of its time. Its directory must not be deleted by hand, as
part of the vault may be in no other file. A device that is still used retires it instead:

1. Read the files of the devices, as for a change of the vault. A device whose `vault.json` is not
   complete, such as one whose newer file has not fully come, or whose file has no `revisionDate`,
   is not retired: the file that stands in for it can be an older one. A device whose `vault.json`
   never comes complete, as that of one that stopped for good while it wrote it, between the
   renames of step 4 of [Changing a vault](#changing-a-vault), or one that a tool that syncs the
   folder damaged, can therefore never be retired. It stays a device that is gone for good: its
   directory is read along with the others, and keeps what it holds, as above.
2. Take its file over into the file of the device: every version of a record in it that is newer
   than the one that the file of the device holds, with its stamp as it is, but for those that it
   holds since a file of it that another device took over (see below). The vault stays the same,
   and a newer version that another device wrote in the meantime still replaces it. Its
   `removedAttachments` are taken over as well, at the current time, but not the attachments that
   the vault has again: the device may not have seen that one that it removed came back, and was
   removed again later by another device, which deletes the content 90 days after that. So are its
   `retiredDevices`: of two notes about the same device, the one about its later file is kept, or
   of two about the same file the one that was made earlier, and a note about this device is left
   out. Its `device` is not: it says what the retired device is.
3. Add a note to `retiredDevices` that the device was retired, with when, which is the current time
   or the latest `revisionDate` of the files that were read if that is later, and the
   `revisionDate` of its file.
4. Leave out what the device no longer has to hold, with the file of the retired device among the
   files of the other devices, and write the file of the device as for a change of the vault, with
   its `revisionDate` set the same way, and `version` set to `3`. A file without `retiredDevices`
   is still written with `version` 2.

A note says that a file of a device was taken over as long as the `revisionDate` of the file is the
one that the note has, or earlier. A device writes each file with a change later than every one
before it (see [Changing a vault](#changing-a-vault)), and a file from before the one that was taken
over, such as the backup of its file, or a copy of its directory from a backup, holds nothing that
the vault is not the same without: what the device left out of its file since was replaced, or
deleted and the deletion forgotten. Every device leaves such a file out of the vault as soon as it
has the note, in whichever file the note is (see
[Putting the vault together](#putting-the-vault-together)), whatever its clock says: the vault is
the same with it or without it.

A later file of the device, which it writes should it be still used after all, still holds what
the file that was taken over held. Every device that has a note about the device in a file that is
not left out leaves that out of the vault: what such a file holds since the file that the latest of
those notes is about, which are the versions whose stamp has an `in` of the `revisionDate` of that
file or earlier, and, of those whose stamp has no `in`, as an earlier client wrote them, those that
the device wrote (`by`) then or earlier (`at`). The device that took that file over holds them, or
what replaced them. Otherwise the device would bring back, with its next change, the items whose
deletions were forgotten since it was retired: it does not know that it was retired until the note
comes to it, which can be after its directory was deleted, if it was not used for long. A note in a
file that is left out does not count for that. The device that took that file over took the note
over with it, but for one about itself: what the file that is left out took over from it is held by
it alone then.

For 90 days after the earliest such note, the time that it can take to come to every device:

- Every device weighs its own file against the file that was taken over as well when it looks for
  what it no longer has to hold: a device that does not have the note yet still puts the vault
  together from it.
- The device that was retired still writes its file from the one that was taken over, should it be
  still used after all. The next time that it looks for what it no longer has to hold, at the
  first sync of its client a day or more after it last did (see
  [What a device no longer has to hold](#what-a-device-no-longer-has-to-hold)), it writes its file
  again with a later `revisionDate`, even if it finds nothing to leave out, as it does when it
  changes the vault: the note is then about a file before, and the device is not retired anymore.
  A device that is still used is thus never retired for longer than a day or so.

After that, the file no longer counts at all. The first device that looks for what it no longer
has to hold deletes the directory of the device, but only if its `vault.json` is complete and is
the file that the note is about, or an earlier one: a file that stands in for it can be older than
a `vault.json` that has not fully come yet, which would be deleted with it. It deletes everything
else in the directory first, then `vault.json`, then the directory: a deletion that stops before it
is done then leaves `vault.json` in its place, and the directory is deleted the next time, where a
file that stands in for it, left on its own, would keep the directory for good. A device that was
retired and is used again after that starts a new file in its directory, as a device that never
wrote one does, with a later `revisionDate` than the file that was taken over: what it held before
is held by the device that retired it.

A device that is still used, but syncs or changes the vault for the first time since it was retired
after the other devices deleted its directory, before that deletion and the note come to it, writes
its file from the one that was taken over, in a directory that the other devices deleted. A tool
that syncs the folder can then keep the deletion of the directory, and the change is lost, or keep
the file, which counts with what came into it since the file that was taken over: its change. Until
the files of the other devices come to it, that file also holds the master password of its time
again. A file of an earlier client does not say when its versions came into it, so what that device
took over from another one before it was retired counts as well, and can bring back the items whose
deletions were forgotten since, and what it wrote later with a clock that was behind is left out.

Notes are kept for good, so that a copy of the directory of a device that comes back, such as one
from a backup, is left out as well. A client that does not know version 3 has no vault to use or to
change once a device of the account was retired, until it is updated (see
[Putting the vault together](#putting-the-vault-together)): it would take `retiredDevices` for part
of the record of the account, and put the vault together from the files that were retired, which
brings back the items whose deletions are forgotten once they are left out.

## Deleting an account

A client that deletes an account first replaces its `vault.json` with the one that says that the
account was deleted (see [vault.json](#vaultjson)), the same way as the file of a device is
replaced. It then deletes everything else in the directory of the account: `vault.json.bak`,
which holds the `vault.json` that was replaced, `vault.json.tmp`, the directories of every device,
`attachments`, and whatever a tool that syncs the folder put there, such as the copies that it
keeps of a `vault.json` that it had two versions of, which can hold a whole vault of the earlier
layout. The directory itself is not deleted.

A tool that syncs the folder brings the deletion to another device one file at a time, and that
device can change the vault before the deletion has fully come to it, which writes its file
again. The tool then keeps that file. Whatever is left in the directory of the account that way is
not an account, as its `vault.json` says. Without that `vault.json`, it would be taken to be an
account whose files are still on their way (see
[Putting the vault together](#putting-the-vault-together)), for good. A client that deletes the
whole directory instead, as the clients did before this `vault.json` was introduced, can leave
such a file behind, and that directory then has to be deleted by hand.

## The earlier layout

In version 1 of this layout, the `vault.json` of an account held the whole vault, in the form of
the file of a device without `records`, `tombstones` and `removedAttachments`. The first device
that changed such a vault took all of it into its own file, and wrote the `vault.json` of version
2 in its place. The versions that it took over have no device in their stamps (`""`): a folder or
an item was taken to have been written at its `revisionDate`, and the records of the account and
of its master password at the `revisionDate` of the vault. They stay in the file of the device
until it no longer has to hold them, as any other version (see
[What a device no longer has to hold](#what-a-device-no-longer-has-to-hold)).

A vault of version 1 is not read anymore. An account whose `vault.json` still is one has no vault
to use or to change, but is not taken to be gone either (see
[Putting the vault together](#putting-the-vault-together)), until a client that still reads that
layout takes it over.

Writing the `vault.json` of version 2 in its place left the vault of version 1 in
`vault.json.bak` of the account, which earlier clients deleted when they synced. That file is not
read either. The `vault.json` of this version is never replaced again, so a backup that is still
there keeps the user key encrypted with the master password of that time for good, after a change
of the master password as well, until it is deleted by hand.

Two devices that took a vault over at once each took all of it, and each holds the same versions
of it until a newer version of the record replaces them.

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

## Sharing a vault between devices

The vault folder can be shared with whatever moves files between devices, such as Syncthing. As
every device writes only its own files, the tool never has two versions of one file to choose
from, and the changes of every device come to every other one. A client notices them the next
time it syncs, by comparing `sync` with what it last read, and then takes over everything that is
in it.

Changes to different records on two devices are all kept. When the same record is changed on two
devices before either has the change of the other, the newer version is kept whole and the other
change is lost, as the content of a record is encrypted and cannot be merged. That goes for the
record of the master password as well: of two changes of the master password at once, one is
kept, and the device whose change was not kept logs the account out when it sees the security
stamp of the other one. The user key stays the same, so every item can still be decrypted. A
change of the rest of the account, such as recording the ID of the user key, is a change of
another record, so it never brings an older master password back.

Deleting an account deletes the files of every device, and leaves its `vault.json` to say that
it was deleted, whatever a device that the deletion has not come to yet writes in the meantime
(see [Deleting an account](#deleting-an-account)).

A device that is gone for good is retired from one that is still used, which takes over what only
it held, and its directory is deleted 90 days later (see [Retiring a device](#retiring-a-device)).
