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

## What the local vault does, and what a client does

The local vault does everything that is the same for every client, so that the clients that
share a vault folder read and write it the same way and answer their requests the same way. It is
used as a Rust crate (`crates/local-vault`), through UniFFI from Kotlin
(`crates/local-vault-uniffi`), or as WebAssembly from JavaScript (`crates/local-vault-wasm`).

| The local vault | A client |
|-----------------|----------|
| What a request asks for: the service it is for, the account of its token, its form, its query, its path decoded | Hands every request for the host `vault.local.invalid` over as it is: method, address, headers, body |
| The route table and the handlers of the identity, account and vault requests | |
| The vault store: the layout of the vault folder, and writes that never leave an account without a complete vault | The file system that reaches the vault folder: six operations |
| The media type of a response, and the error body for a call that fails unexpectedly | Turns the response into one of its HTTP client |
| Where the content of an attachment is stored, and which file a download is | Stores and reads that content, if it streams it |
| Which accounts a vault folder does not have yet | Copies them when the vault moves to another folder |
| The rules that a client checks itself against | Its tests that check them |

### The local server

`LocalServer::handle_http` takes an `HttpRequest` and gives an `HttpResponse`. The address is the
full address, such as `https://vault.local.invalid/api/sync`, and the path that the routes see is
relative to the service: `api`, `identity` and `events` are taken off, so one route table serves
all three. An address without a host, such as `/sync`, is taken as well. The `Authorization`
header gives the account, and a body with the media type `application/x-www-form-urlencoded` is
read as a form.

Five properties hold for every client:

- **One request at a time.** Every change reads the whole vault and replaces it, so requests are
  handled under a single lock.
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
master password hint (`ClientKind`), as each client shows the message of another status.

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

The vault store keeps one directory per account, named after the ID of the account, with a
single `vault.json` and the encrypted attachments next to it. It is the only code that knows the
file layout, and it guarantees three things:

- A write never leaves an account without a complete vault: the new content goes to a temporary
  file, the old file becomes the backup, and the temporary file takes its place.
- A vault with a format or a version that is not known is left alone, and its older backup is
  not used in its place.
- A name that comes from a request is only used as a file name if it consists of letters,
  digits, `-` and `_` (`is_safe_segment`), so that no request can reach outside the vault folder.

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

## How each job of the server is done

| Job of the server | What happens instead |
|-------------------|----------------------|
| Verify the email address at registration | No email is sent. The request that would send it returns the verification token right away, as a server with email verification turned off does. |
| Create the account | `vault.json` is created from the keys that the client generated, under a new UUID as the account ID. |
| Tell the client how to derive the master key | The KDF settings are read from the vault of the account with that email address, which is the one with the lowest ID if there are several. An unknown address gets the defaults. |
| Check the master password | The client sends the same password hash it sends to a server. It is checked against a salted verifier in the vault, which is the counterpart of the hash a server stores. |
| Find the account that logs in | The account directories are searched for the ones with that email address. They are gone through in the order of their IDs, and the first one that the master password is right for is logged in to. Nothing is registered per device, so a device that is given a vault folder can log in to the accounts in it. |
| Issue tokens | An access token in the shape of the JWT that the identity server issues, carrying the account ID, and a refresh token. Neither is signed, and they are valid for years: they never leave the process, and what they give access to is encrypted with keys they do not hold. |
| Return the vault | The `sync` part of `vault.json` is the body of the response to `GET /sync`, and is returned as it is. |
| Store a change | The vault is read, changed and written back as a whole. |
| Refuse to overwrite a newer item | An item is only replaced if the revision date that the client knows it by is the one in the vault, within a second. |
| Refuse an item of another account | A request that stores an item says in `encryptedFor` which account the client encrypted it for. If that is not the account of the token, the request is refused, as the item could not be decrypted in the vault that it would be stored in. One such item refuses a whole import. |
| Refuse an item of another key | A client can have the ID of the user key recorded in the vault, which the SDK of the browser extension does. An item that says in `encryptedByKeyId` that it was encrypted with another key is then refused, as it is from a client that has another user key than the vault. |
| Import into a folder that exists | A folder that an import comes with is the folder of the vault with that ID, if there is one. Only a folder without an ID, or with one that the vault does not have, is added, under a new ID. |
| Store attachments | The client is given an upload URL on the reserved host, as it would be given one for cloud storage. The local server answers that URL as well. Downloads work the same way. |
| Delete an attachment or an item | The vault is saved without it first, and the files of its attachments are deleted after. Files that cannot be deleted do not fail the request, which has done what it is for: they are logged and left behind. |
| Delete the account | The directory of the account is deleted. If anything of it remains, the request fails, so that the client does not log the account out as if it were gone. |
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

Three mechanisms make this work, and the local vault implements them for every client.

**Noticing a change from outside.** Before a sync, a client asks when the vault last changed and
skips the sync if that is before its last sync. A file that a sync tool brought in can carry a
date that is older than that, so the date alone cannot be trusted. The local server therefore
remembers the content it last returned in full, and reports the vault as changed just now
whenever the content on disk is anything else.

**Conflicting changes.** Within one device, an item that changed since the client last saw it is
not overwritten: the request is refused and the client asks the user to sync. Across devices
there is no merging. The vault is one file, so when two devices change it before they exchange
it, the sync tool picks one version and the changes in the other are lost. Copies that a tool
keeps of the losing version are not read by anything.

**Changing the master password.** The change replaces the verifier and the encrypted user key,
and gives the account a new security stamp. Every other client sees the new stamp at its next
sync and logs the account out, as its copy of the user key is unlocked with the old password.

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
2. **Give the local vault the file system of the client**, and run `check_file_system` against
   it. Test it against a vault folder that another client created.
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
7. **Add the setting for the vault folder**, with a copy of `accounts_missing_in` that never
   overwrites an account that is already in the chosen folder.
8. **Test with two clients on one folder**: register on one and log in on the other, change an
   item on both, and change the master password on one to see the other log out.

## Limits to keep in mind

- **Changes on two devices at once lose one side.** The unit of exchange is the whole vault
  file. Merging per item would need a change of the format.
- **The lock only holds inside one process.** Two clients on one machine that use the same
  folder, or a sync tool that replaces the file between a read and a write, can lose a change.
  Version 1 of the format has no lock file.
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
- **Files of attachments can be left behind.** A file that could not be deleted stays in the
  folder when its item is gone, and goes to every device that shares the folder. Nothing looks
  for files that no item refers to.
