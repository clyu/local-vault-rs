# The local vault: design

The decentralized Bitwarden clients work without a Bitwarden server. Everything a server would
have stored is kept in files, and devices share a vault by sharing those files. This document
explains the design that every client shares, and what a client has to bring to it. It is written
for whoever makes another Bitwarden client (desktop, iOS, CLI) work the same way.

The exact layout of the shared files is specified in [LOCAL_VAULT_FORMAT.md](LOCAL_VAULT_FORMAT.md),
which is the contract between clients. What is particular to a client is documented with it: in
`docs/DECENTRALIZATION.md` of the Android app, and in `apps/browser/src/local-vault/README.md` of
the browser extension.

- [What decentralized means here](#what-decentralized-means-here)
- [The approach](#the-approach)
- [What the local vault does, and what a client does](#what-the-local-vault-does-and-what-a-client-does)
- [How each job of the server is done](#how-each-job-of-the-server-is-done)
- [Making sure nothing reaches a real server](#making-sure-nothing-reaches-a-real-server)
- [Sharing a vault between devices and clients](#sharing-a-vault-between-devices-and-clients)
- [What works and what does not](#what-works-and-what-does-not)
- [Porting this to another client](#porting-this-to-another-client)
- [Limits to keep in mind](#limits-to-keep-in-mind)

## What decentralized means here

- **There is no server.** No request about the vault leaves the device. An account exists only
  as a directory of files.
- **Every device holds the whole vault.** A device can register, log in, read and change the
  vault with no network at all.
- **Moving the files is somebody else's job.** A client never talks to another device. The user
  keeps the vault folder under any tool that moves files between devices, such as Syncthing, a
  cloud drive or a manual copy, and the client only notices that the files changed.
- **Zero-knowledge is unchanged.** The files hold what the server used to hold and nothing more:
  everything secret is encrypted by the Bitwarden SDK before it is stored, with keys that only
  the master password unlocks.

## The approach

A client is not rewritten to work on files. Instead, the server is replaced by a stand-in that
runs inside the client and answers the same HTTP API from the files. This stand-in is the
**local server**, and the files it works on are the **local vault**. The local server is not a
server in the networking sense: it opens no socket, and is a function from a request to a
response that the HTTP client of the client calls instead of going to the network.

```
UI, view models, repositories, SDK         unchanged
API services                               unchanged
HTTP client
  +- interception point                    the client: hands over requests as they are
       +- local vault (this repository)    routes, handlers, vault store
            +- file system                 the client: the vault folder
                                                    ^
                                                    |  any file sync tool
                                                    v
                                         other devices and clients
```

The HTTP boundary was chosen for these reasons:

- **Nothing above it has to change.** Login, unlock, sync, autofill, the local database and the
  encryption all work as before, because from where they stand a server still answers.
- **The security model is inherited.** The local server sees exactly what a Bitwarden server
  sees: password hashes and encrypted data. No decision about what may be stored unencrypted
  had to be made again.
- **It ports.** Every Bitwarden client already speaks this API, so every client can be given the
  same stand-in at the same place.
- **Updates from upstream stay cheap.** New features keep working as long as the requests they
  make are answered, and the checks below report the ones that are not.

The database and the settings that a client already had are still what they were: a cache of
what "the server" holds. Only the server behind them is now the vault folder.

The first of the reasons above is the one that decided where the boundary is. The clients are
forks, and each file of upstream that a fork changes is one that every update from upstream has
to be merged into. The boundary therefore also holds for what the local vault takes on: what a
Bitwarden server would do with a request, and never what a client does when it talks to a server,
such as putting a request together or reading a response into its models. That stays in the code
that the clients have from upstream, even where every client does it the same way, as a client
could only hand it over by changing that code.

## What the local vault does, and what a client does

The local vault does the work of a Bitwarden server for every client, so that the clients that
share a vault folder read and write it the same way and answer their requests the same way. It is
used as a Rust crate (`crates/local-vault`), through UniFFI from Kotlin
(`crates/local-vault-uniffi`), or as WebAssembly from JavaScript (`crates/local-vault-wasm`).

Besides the work of the server, the local vault only has code that the forks added to the clients
and that is the same in all of them, such as the rules that a client checks itself against and
what it copies when the vault moves to another folder. Code that the clients have from upstream
never moves into the local vault, and neither does code whose move would change a file of
upstream (see [The approach](#the-approach)).

| The local vault | A client |
|-----------------|----------|
| What a request asks for: the service it is for, the account of its token, its form, its query, its path decoded | Hands every request for the host `vault.local.invalid` over as it is: method, address, headers, body |
| The route table and the handlers of the identity, account and vault requests | |
| The vault store: the layout of the vault folder, the vault put together from the files of every device, and writes that never leave a device without a complete file | The file system that reaches the vault folder: six operations |
| The directory that a device writes in | The ID of its installation, which is the same every time it starts |
| The media type of a response, and the error body for a call that fails unexpectedly | Turns the response into one of its HTTP client |
| Where the content of an attachment is stored, and which file a download is | Stores and reads that content, if it streams it |
| Which accounts a vault folder does not have yet, and what it does not have yet of the others: the files of the device, and the content of attachments | Copies them when the vault moves to another folder |
| The rules that a client checks itself against | Its tests that check them |

### The local server

`LocalServer::handle_http` takes an `HttpRequest` and gives an `HttpResponse`. The address is the
full address, such as `https://vault.local.invalid/api/sync`, and the path that the routes see is
relative to the service: `api`, `identity` and `events` are taken off, so one route table serves
all three. An address without a host, such as `/sync`, is taken as well. The `Authorization`
header gives the account, and a body with the media type `application/x-www-form-urlencoded` is
read as a form.

Five properties hold for every client:

- **One request at a time.** Every change reads the whole vault and writes what changed in it,
  so requests are handled under a single lock.
- **It never fails in a way a client cannot show.** A malformed request gets a 400, both in the
  error format of the Bitwarden API. A vault folder that cannot be read fails the call, which a
  client reports as a request that did not reach its server. A call that fails in any other way
  is answered by the client with `INTERNAL_ERROR_JSON` and a 500.
- **It works on JSON as it comes, not on typed models.** Everything is stored in the form the
  server returns it in. A request body is turned into that form by setting the few fields that
  the server owns (IDs, dates, permissions), leaving out the few that are about the request and
  not about the item (such as `lastKnownRevisionDate` and `encryptedFor`), and keeping the rest
  as sent. Fields that a newer client or SDK adds survive without the local server knowing them.
- **Every request gets one of three kinds of answer:** an answer from the vault; a constant, for
  requests there is nothing to do for (registering a push token, reporting events, listing
  devices); or a refusal that says the feature needs a Bitwarden server, which a client shows as
  an ordinary error message. Whether there is a route for a request is looked at before whose
  request it is. A request that is refused for want of a route is logged with its method and
  path, with a `*` in place of every segment that is not a word of the API, so that nothing that
  identifies an item or an account is logged. That log is what shows a request that an update
  from upstream started to make.
- **The vault says how an ID is written, not the request.** IDs are compared without regard to
  case. Once an item, a folder or an attachment is found, the ID that the vault has is the one
  that is stored again and the one that the files of attachments are named after. An item or a
  folder is only taken to be named in a path by a UUID, which keeps a request such as
  `DELETE ciphers/admin` from being taken for one.

The one thing that the local server does differently for each client is the status of the
master password hint (`ClientKind`), as each client shows the message of another status. What it
does differently for each device is where it writes: a client gives its local server the ID of
its installation when it creates it, and the local server writes in a directory named after it.

### The content of attachments

The content of an attachment can be large, and a client may have it as a stream. There are two
ways to hand it over:

- **Streamed** (`handle_http`). The client leaves the body of a request to an address that
  `streams_request_body` is `true` for out of the request, and stores it where the response says
  (`store_request_body_at`) before it gives the response to its caller. A response whose body is
  a file (`ResponseBody::File`) is read by the client. The Android app does this, as a folder of
  the user is reached as streams.
- **Buffered** (`handle_http_buffered`). The client gives the whole body, and the local server
  stores it and reads the file of a response itself, under the same lock as the request. The
  browser extension does this, as it has the content in memory anyway.

### The vault store

The vault store keeps one directory per account, named after the ID of the account. In it, every
device writes a file of its own, which no other device writes, and the encrypted attachments are
next to them. The vault is put together from the files of all devices: each file holds versions
of records (the master password, the rest of the account, a folder or an item), each with a
stamp of when and by which device it was written, and the vault is the newest version of each
record (`merge.rs`). The handlers do not know about any of this: they get the whole vault and
give back the whole vault, and the store writes what changed between the two to the file of the
device. It is the only code that knows the file layout, and it guarantees five things:

- A device only ever writes its own files, apart from `vault.json` of an account, which says
  which layout the account has, or that the account was deleted, and is the same on every
  device, and its backup, which is deleted once it holds a vault of the earlier layout that a
  device took over. A tool that syncs the folder never has to choose between two versions of a
  file.
- A write never leaves a device without a complete file: the new content goes to a temporary
  file, the old file becomes the backup, and the temporary file takes its place.
- A change that is made after another one is newer than that one, even where the clock of the
  device is behind: its stamp is later than that of the version that it replaces.
- A file with a format or a version that is not known keeps the whole vault of its account from
  being used or written, and its older backup is not used in its place. The account is not taken
  to be gone for it: a newer client wrote the file (see below).
- A name that comes from a request is only used as a file name if it consists of letters,
  digits, `-` and `_` (`is_safe_segment`), so that no request can reach outside the vault folder.

A device leaves out of its file what it no longer has to hold: a version that another device has
a newer one of, or the same one if the ID of that device comes first, and a deletion that is old
enough and that nothing could bring back anymore. The deletion of a folder is kept while a file
has an item in the folder, which would otherwise be in a folder that is not there. A version of a
record that another device deleted since is replaced by that deletion. A device does this when it
writes its file, and when its client syncs, once a day at most, and again at the next sync if it
could not, as it is also what leaves an older master password out.

A tool that syncs the folder brings the files of an account in no particular order, so a third
device can get the file that leaves a version out before the file with the newer one. A device
therefore holds a version until the newer one has been in the file of the other device for 90
days, the time that the format allows a file to take to come to every device (`GRACE_MILLIS`),
and the third device has the record in the meantime, if not yet as it is now. Every file says
since when it is there (`since`), as a version that a device took over from a vault of the
earlier layout is much older than the file that holds it. One version is left out right away:
one of the master password, as its older versions hold what a change of the master password
replaced. A version that a deletion replaced is replaced by that deletion right away, rather than
left out: the device that deleted the record put the deletion in place of the version that it
held, so a third device that gets the file without the version before the file with the deletion
can still have the file of that device from before, with an older version, which it would take
for the record.

The content of an attachment is a file that every device shares, not a version, and a device
that had not seen the removal of an attachment can bring it back with a change of the item that
is newer. So a device that removes an attachment, or deletes an item or purges the vault, only
notes the attachments that it took out of its vault in its file (`removedAttachments`), and
deletes their content when it tidies its file, once they have been removed for 90 days and the
vault does not have them again. If the vault has one again, the note is dropped and the content
kept. Purging thus only reaches the attachments of the items that the device has, and never the
content of an item whose file has not come yet. The content is deleted file by file, and the
directory that held the content of an item only once it is empty, and only if the vault does not
have the item: a directory is deleted with everything in it, and the content of a new attachment
of an item that the vault has can be on its way to it.

A device can also have the `vault.json` that says that an account has this layout, or the file
of another device, before any file with the record of the account: that of the device that took a
vault of the earlier layout over, or that of the device that holds the newer record when the file
that left the older one out came first. Such an account is not taken to be gone, as a 401 or a
refresh token that is refused would make the client log it out. Its requests fail as ones that did
not reach the server, which the client tries again. Its email is not known until the file comes,
so a request that looks for an account by an email that no other account has fails the same way:
told that no account has the email, the client would derive the master key with the default KDF
settings, take the master password to be wrong, or register the address again. An account with a
file of a layout that is not known is treated the same way until the client is updated, as a
newer client wrote that file. The next change of the layout can thus reach one client before
another: the one that is not updated yet cannot use the account, but neither logs it out nor lets
its email be registered again. As a client says no more than that its request did not reach the
server, the local server logs the ID of such an account, which is the name of its directory: one
whose files will never all come has to be found to be deleted by hand (see
[Limits to keep in mind](#limits-to-keep-in-mind)).

What is left of an account that was deleted must therefore never look like that. A tool that
syncs the folder brings a deletion to another device one file at a time, and that device can
write its file again in the meantime, which the tool then keeps. So deleting an account does not
delete its directory: it replaces its `vault.json` with one that says that the account was
deleted, and deletes everything else. Whatever is left in the directory, or written there again,
is not read from then on, and a client that does not know that `vault.json` takes it for a layout
that it does not know, which it leaves alone.

For the same reason, the `vault.json` that says that an account has this layout is only written
by the device that the account first has a file of, which holds the record of the account: the
one that registers the account, or that takes a vault of the earlier layout over. Another device
gets it from that one. If it wrote it as well, it could do so as the account is deleted, and a
tool that syncs the folder could keep its `vault.json` in place of the one that says that the
account was deleted, and delete the file with the record of the account all the same: the account
would be taken to be on its way for good, and no address that no other account has could be
registered in the folder. A `vault.json` that cannot be written does not fail the change, which
is in the file of the device by then, and would be made twice if the client tried it again: the
next change writes it, unless another device has a file of the account by then, and then no
device writes it. The account is used all the same, as the files of its devices hold its records:
only a device that has none of those files yet takes it to be not there, as before any file of it
has come, rather than on its way.

A client that knows only the earlier layout can still write a vault of that layout after a device
took it over, until the `vault.json` of this layout has come to it, and a tool that syncs the
folder can keep that vault in place of the `vault.json`. That client rewrites the whole vault for
any change, and its records of the account and of the master password have no stamp but the
revision date of the vault, which every change moves on. So such a vault never wins over what a
device wrote of the account or of the master password: any change on that client would otherwise
bring back a master password that a device replaced. What it no longer has of what a device took
over, it deleted, unless a device changed it since (`merge::after_take_over`).

### The file system

The store does not use files directly but a `FileSystem` with six operations: list, exists, read,
write, rename and delete. Paths are lists of names relative to the vault folder. The operations
are asynchronous, as the browser extension reaches the folder through messages to another
program; a client whose file system answers right away waits for the local server on the thread
of the call.

Interoperability stands or falls with this layer, so its rules are checks as well:
`check_file_system` runs them in a directory of its own and returns the ones that a file system
does not keep. A place that cannot rename a file over another one is allowed, as the folder that
the Android app reaches through the Storage Access Framework cannot, and the store works around
it.

### Moving the vault to another folder

`accounts_missing_in` gives the accounts that a folder has and another one does not. A client
that moves the vault copies those, with everything in them, and never an account that the other
folder already has, which is what makes it safe to choose a folder that another device has
filled.

Of an account that both folders have, `device_files_missing_in` gives what the other folder does
not have yet of what the device wrote: the files of its own directory that the other folder has
otherwise or not at all, and the content of attachments that the other folder does not have. No
other device writes that directory, so the files of the folder that the vault is in are the ones
that the device wrote last, as when the other folder was filled with a copy of the vault from
before its last changes. The client copies them as well, in the order that they come in: the
content of attachments before the file that lists them, and the `vault.json` of the device last,
so that a copy that is interrupted leaves the earlier file in its place. It never copies the files
of another device, as those of the other folder are on their way to it, and a copy could replace
a newer one of the device that wrote it.

## How each job of the server is done

| Job of the server | What happens instead |
|-------------------|----------------------|
| Verify the email address at registration | No email is sent. The request that would send it returns the verification token right away, as a server with email verification turned off does. |
| Create the account | The file of the device is created from the keys that the client generated, under a new UUID as the account ID. |
| Refuse KDF settings that it does not take | A registration and a change of the KDF settings are refused if the settings are outside of the ranges that the Bitwarden server takes them in: PBKDF2-SHA256 with 600 000 to 2 000 000 iterations, or Argon2id with 2 to 10 iterations, 15 to 1024 MiB of memory and a parallelism of 1 to 16. So are the settings of another KDF, which the server does not check. A change of the master password is refused if it comes with other settings than the account has, as with the server: only a change of the settings changes them. Settings that an account already has are not checked again, so an account that an earlier version took other settings for still logs in and changes its master password. |
| Tell the client how to derive the master key | The KDF settings are read from the vault of the account with that email address, which is the one with the lowest ID if there are several. An unknown address gets the defaults, unless the vault of an account is still on its way to the device, or has a layout that is not known, as the address may be its: the request then fails as one that did not reach the server. |
| Check the master password | The client sends the same password hash it sends to a server. It is checked against a salted verifier in the vault, which is the counterpart of the hash a server stores. |
| Find the account that logs in | The account directories are searched for the ones with that email address. They are gone through in the order of their IDs, and the first one that the master password is right for is logged in to. Nothing is registered per device, so a device that is given a vault folder can log in to the accounts in it. |
| Issue tokens | An access token in the shape of the JWT that the identity server issues, carrying the account ID, and a refresh token. Neither is signed, and they are valid for years: they never leave the process, and what they give access to is encrypted with keys they do not hold. |
| Return the vault | The `sync` part of the vault, put together from the files of every device, is the body of the response to `GET /sync`. |
| Store a change | The vault is read and changed as a whole, and what changed is written to the file of the device. |
| Refuse to overwrite a newer item | An item is only replaced if the revision date that the client knows it by is the one in the vault, within a second. |
| Refuse an item of another account | A request that stores an item says in `encryptedFor` which account the client encrypted it for. If that is not the account of the token, the request is refused, as the item could not be decrypted in the vault that it would be stored in. One such item refuses a whole import. |
| Refuse an item of another key | A client can have the ID of the user key recorded in the vault, which the SDK of the browser extension does. An item that says in `encryptedByKeyId` that it was encrypted with another key is then refused, as it is from a client that has another user key than the vault. |
| Import into a folder that exists | A folder that an import comes with is the folder of the vault with that ID, if there is one. Only a folder without an ID, or with one that the vault does not have, is added, under a new ID. |
| Store attachments | The client is given an upload URL on the reserved host, as it would be given one for cloud storage. The local server answers that URL as well. Downloads work the same way. |
| Delete an attachment or an item | The vault is saved without it, and the attachments that it took out are noted in the file of the device. Their content is deleted 90 days later, when the device tidies its file, unless a change of another device brought them back in the meantime. Content that cannot be deleted then is deleted the next time. Until then it is not handed out. |
| Delete the account | The `vault.json` of the account is replaced by one that says that the account was deleted, and everything else in its directory is deleted, what a tool that syncs the folder put there included: its copies of a `vault.json` that it had two versions of can hold a whole vault of the earlier layout. If that `vault.json` cannot be written, the request fails, so that the client does not log the account out as if it were gone. Files that cannot be deleted after it are logged and left behind, as nothing reads them. |
| Email the master password hint | The hint is returned in the response and shown by the client. |
| Sell premium | Every account is reported as premium. |
| Report feature flags | None are reported. |
| Push changes to other devices | Nothing is pushed. A device finds out about a change the next time it syncs. |

## Making sure nothing reaches a real server

Answering requests is not enough: a request that is not answered must not find its way to a
server either. Three measures see to that, and every client takes all of them.

1. **The addresses of the server are replaced by one that cannot exist.** Every service is at
   `https://vault.local.invalid`. `.invalid` is a reserved top-level domain that never resolves,
   so a request that slips past the local server fails instead of leaving the device.
2. **The SDK is given the same addresses.** The Bitwarden SDK can make requests by itself. In the
   browser extension they pass the interception point like any other, as the SDK uses `fetch`.
   In the Android app they do not, as the SDK has an HTTP client of its own, and with an address
   that does not resolve, they fail.
3. **No feature flags are reported.** Some flags hand a whole step to the SDK, requests
   included, or lead to requests that the local server refuses. Without flags a client stays on
   the code paths that go through its own HTTP client. `FLAGS_THAT_MUST_BE_OFF` lists the flags
   that this depends on, by name and by the clients that have them, and every client checks that
   each of its own is still there and off by default: a flag that upstream removes is a code
   path that is then always taken.

What still leaves the device is what never went to the vault API in the first place, such as
checking a password against Have I Been Pwned, and loading the website icons of items, which tell
the icon service which websites are in the vault unless the user turns them off.

## Sharing a vault between devices and clients

For the user, sharing a vault takes three steps: choose a vault folder on the first device, let
a file sync tool carry it to the second device, and choose it as the vault folder there. The
second device then logs in with the email address and the master password. There is nothing to
register, and registering the address again must be avoided: on a device that the account has
not arrived on yet, it makes a second account with the same address instead of opening the
first (see [Limits to keep in mind](#limits-to-keep-in-mind)).

Four mechanisms make this work, and the local vault implements them for every client.

**Noticing a change from outside.** Before a sync, a client asks when the vault last changed and
skips the sync if that is before its last sync. A file that a sync tool brought in can carry a
date that is older than that, so the date alone cannot be trusted. The local server therefore
remembers the content it last returned in full, and reports the vault as changed just now
whenever the content on disk is anything else.

**Conflicting changes.** Within one device, an item that changed since the client last saw it is
not overwritten: the request is refused and the client asks the user to sync. Across devices,
every device writes only its own file, so the changes of both come through, and the vault is put
together from them record by record. Only when two devices change the same record before they
exchange their files does one change win: the one with the later stamp, as the content of a
record is encrypted and cannot be merged. The master password is a record of its own, apart
from the rest of the account: it is never put together from two changes, and a change of the
rest of the account, which a device can make before the newest master password has come to it,
never brings an older one back. Deleting a folder does not change the items in it, which are in
no folder as the vault is put together, so that it does not win over a change of one of them on
another device.

**Changing the master password.** The change replaces the verifier and the encrypted user key,
and gives the account a new security stamp. Every other client sees the new stamp at its next
sync and logs the account out, as its copy of the user key is unlocked with the old password.
A client derives the new master key with the KDF settings that the account has, and not with
the ones that it was unlocked with, which are the settings from before once it changed them
itself, or synced a change of them from another device (see below). The vault takes a new master
password only with the settings of the account, but cannot tell whether the user key is encrypted
with a master key that they derive: an account whose user key is encrypted with another one can
never be unlocked again.

**Changing the KDF settings.** The change replaces the verifier and the encrypted user key as
well, with those of the master key that the new settings derive, but keeps the user key and the
security stamp, so no client is logged out. Every other client takes the new settings at its next
sync. Until then it still unlocks the vault with the settings from before, as its copy of the
user key is encrypted with the master key that they derive, but a request with which it proves
the master password, such as deleting the account or changing the settings again, is refused as
if the master password were wrong: the hash that it derives with the settings from before is not
the one that the vault knows the master password by. A client therefore syncs before it changes
the settings. Logging in is not affected, as a client asks how to derive the master key first.

## What works and what does not

| Works | Does not work, as it needs a server |
|-------|-------------------------------------|
| Registering and deleting an account | Organizations, collections and sharing items |
| Logging in with the master password | Sends |
| Items: add, edit, trash, restore, delete, archive | Two-step login |
| Folders | Single sign-on, Key Connector and trusted devices |
| Attachments | Logging in with a device or with admin approval |
| Importing from another password manager | Buying or managing a subscription |
| Changing the master password and the KDF settings | Policies |
| Master password hint | Real-time sync by push notification |
| Several accounts in one vault folder | |

What a client asks for request by request is in its own tests: `LocalServerEndpointInventoryTest`
of the Android app, and `endpoint-inventory.spec.ts` of the browser extension.

## Porting this to another client

The file format, the route table, the handlers and the store are the local vault, which another
client uses rather than ports. The parts that differ per client are the interception point, the
file system and the setting for the vault folder. A workable order:

1. **Find the one place that all requests to Bitwarden pass through**, and hand the requests for
   `vault.local.invalid` to the local server there, in the same process, as they are. Check for a
   second path that bypasses it, such as requests that the SDK makes by itself.
2. **Give the local vault the file system of the client** and the ID of its installation, and
   run `check_file_system` against the file system. Test it against a vault folder that another
   client created.
3. **Turn the responses into those of the HTTP client**, with their media type, and choose
   whether the content of attachments is streamed or buffered.
4. **List every request that the client can make**, and check each of them with `is_answered`.
   A request that a client needs and that is refused gets a route in the local vault, for every
   client. A request that disappears from a client deserves a look too: it may have moved into
   the SDK.
5. **Match what the server does, not only what it returns.** Clients depend on details such as
   which requests return the changed item and which do not, as the revision date that a client
   knows an item by follows from it. Running the real API services of the client against the
   local server finds most of these.
6. **Close the ways out**: unreachable addresses for the client and the SDK, no feature flags,
   a test that the flags of `FLAGS_THAT_MUST_BE_OFF` that the client has are off, and no
   refusing to work when offline.
7. **Add the setting for the vault folder.** When the vault moves to the chosen folder, the
   client copies what `accounts_missing_in` and `device_files_missing_in` give, in the order that
   they give it in, and nothing else, which never overwrites an account that the folder already
   has (see [Moving the vault to another folder](#moving-the-vault-to-another-folder)). It calls
   them rather than holding a copy of them, and does only the copying, as a stream.
8. **Test with two clients on one folder**: register on one and log in on the other, change an
   item on both, and change the master password on one to see the other log out. Then change the
   KDF settings on one and the master password on the other, without locking the other in
   between, and the settings and then the master password on one client, without locking it
   either: each time, the new master password has to log in and unlock on both clients. A client
   that derives the new master key with the settings that it was unlocked with then leaves an
   account that can never be unlocked again (see
   [Sharing a vault between devices and clients](#sharing-a-vault-between-devices-and-clients)).

## Limits to keep in mind

- **Changes to the same record on two devices at once keep only the later one.** Records are
  encrypted, so the newer version of an item, a folder, the master password or the rest of the
  account replaces the other one whole.
- **The lock only holds inside one process.** Two clients on one machine that use the same
  folder with the same device ID can lose a change. With their own device IDs, as two
  installations have, they write different files.
- **The directory of a device must not be deleted by hand.** Part of the vault may only be in
  it. A device that is gone for good leaves its directory behind, which is read along with the
  others.
- **Changing the master password does not lock out whoever knows the old one.** Nothing changes
  the user key, and the user key encrypted with the old master key stays in the folder: a device
  leaves the older master password out of its file only the next time that it syncs or
  changes the vault, the backup of the file keeps it until the file is written again, and the
  directory of a device that is gone for good, such as that of a browser extension that was
  installed again, keeps it for good. Whoever has the old master password and a copy of the
  folder can therefore decrypt the vault, items added after the change included. If the master
  password may be known to someone else, export the vault, import it into a new account, and
  delete the old account, which deletes the files of every device.
- **Stronger KDF settings do not protect what the folder held before.** The user key encrypted
  with the master key of the settings from before stays in the folder in the same places as after
  a change of the master password, and is in every copy of the folder from before the change: the
  master password is as easy to guess from it as it was.
- **A deletion is forgotten after 90 days** once no other file holds the record. A device that
  changed the record before it was deleted and comes back later than that brings it back.
- **A version that another device replaced is kept for 90 days.** A device that gets the files
  of the others later than that, and in another order than they were written, can be without
  an item until the file with its newer version comes too.
- **Changes arrive at the next sync, not as they happen.** Nothing watches the vault folder.
- **Unsigned tokens and open attachment URLs are only acceptable in-process.** If a platform
  forces the local server to listen on a real socket, both need real protection first.
- **Whoever can read the vault folder is in the position of the server.** That includes the
  email address, the name, the master password hint, how many items there are and when they
  changed, and the chance to guess the master password offline. A hosted server keeps this
  behind its own defenses; a synced folder may not. A strong master password and KDF settings
  matter more here than with a server.
- **The email address is only a label.** Nobody verifies it. It serves to find the account in
  the folder at login.
- **Two accounts can have the same email address.** Registration only looks at the accounts
  that are in the folder at that moment, so registering an address again on a device that the
  first account has not arrived on, or putting the account directories of two folders together,
  leaves two of them. The master password tells them apart at login, and every client goes
  through them in the same order, which
  [LOCAL_VAULT_FORMAT.md](LOCAL_VAULT_FORMAT.md#accounts-with-the-same-email-address) lays
  down. Nobody is told that there are two, and one that has the master password of an account
  before it, or that derives its master key in another way than the first one, cannot be logged
  in to.
- **The content of a removed attachment stays for 90 days.** It is encrypted, and not handed
  out, but it is in the folder until the device that removed it tidies its file after that, so
  that a change of another device can still bring the attachment back. A change that comes later
  than that brings the attachment back without its content.
- **Files of attachments can be left behind.** The content of an attachment that a device
  removed stays in the folder if that device is gone for good, and goes to every device that
  shares the folder. Nothing looks for files that no item refers to. An item that the vault
  still has keeps the directory of the content of its attachments once the last of them is
  gone, empty.
- **A deleted account leaves its directory behind**, with the `vault.json` that says that it was
  deleted, and the file of any device that wrote it again before the deletion came to it. A
  client that deletes the whole directory instead, as the clients did before that `vault.json`
  was introduced, can leave such a file behind without it, which is then taken to be an account
  on its way for good, and so can deleting the directory of a device by hand. Until such a
  directory is deleted by hand, the requests of the account fail, and so does every request that
  looks for an account by an email that no other account has, on every device that shares the
  folder. The local server logs the ID of the account, which is the name of the directory. Its
  files tell it as well: its `vault.json` is missing or says that it has this layout, and none of
  the files in its `devices` has `account` in its `records`, or none has `masterPassword` there.
