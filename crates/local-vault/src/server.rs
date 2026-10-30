use std::collections::HashMap;

use futures::lock::Mutex;
use serde_json::{Value, json};

use crate::account::{profile, user_key_rotation, verify_password};
use crate::date::format_date;
use crate::fs::{FileSystem, IoError};
use crate::http::{
    InvalidRequest, LocalRequest, LocalResponse, ResponseBody, invalid_request_response, is_uuid,
    list_response, ok_empty_response, ok_response, unauthorized_response, unsupported_response,
};
use crate::json::{JsonObject, is_safe_segment, with_fields};
use crate::merge::DeviceDescription;
use crate::platform::{LogLevel, Platform, new_uuid};
use crate::store::{KEY_REVISION_DATE, LocalVaultStore, ReadError, ReadVault, as_strs};
use crate::token::bearer_of_access_token;
use crate::vault::{ATTACHMENTS_PATH, get_attachment, get_cipher, get_folder, renew_attachment};
use crate::withheld::{Returned, withhold};

/// The version of the Bitwarden server that the local server says it is.
const SERVER_VERSION: &str = "2026.9.0";

const ATTACHMENT_GONE_MESSAGE: &str = "The content of the attachment is gone.";

const DEVICE_ID_MESSAGE: &str =
    "The device ID is made of 1 to 128 ASCII letters, digits, \"-\" and \"_\".";

const TIDY_FAILED_MESSAGE: &str =
    "Local server could not leave out of its file what other devices replaced.";

/// How often the local server looks for what its file of an account no longer has to hold.
const TIDY_INTERVAL_MILLIS: i64 = 24 * 60 * 60 * 1000;

/// The client that the local server answers, for the one thing that it does differently for
/// each: what tells the client the master password hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientKind {
    /// The Android app, which shows the message of an error only for `429 Too Many Requests`.
    Android,
    /// The browser extension, which shows its own message for `429 Too Many Requests`.
    Browser,
}

/// A feature flag that the local vault counts on to be off. The local server reports no flags,
/// so a client gives each flag the value that it has by default, and a flag of these moves
/// requests to where the local server does not follow them when it is on: into the Bitwarden
/// SDK, which makes them by itself and which the Android app does not hand to the local server,
/// or to routes that the local server refuses.
///
/// Every client checks that the flags that it has are off by default, and that they are still
/// there: a flag that upstream removes is a code path that is then always taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlagRule {
    /// The name of the flag, which is the same in every client that has it.
    pub key: &'static str,
    /// The clients that have the flag.
    pub clients: &'static [ClientKind],
    /// What a client does when the flag is on.
    pub reason: &'static str,
}

/// The feature flags that the local vault counts on to be off.
pub const FLAGS_THAT_MUST_BE_OFF: &[FlagRule] = &[
    FlagRule {
        key: "pm-27632-cipher-crud-operations-to-sdk",
        clients: &[ClientKind::Browser],
        reason: "the SDK saves, changes and deletes items",
    },
    FlagRule {
        key: "pm-28192-cipher-attachment-ops-to-sdk",
        clients: &[ClientKind::Browser],
        reason: "the SDK makes the requests for attachments",
    },
    FlagRule {
        key: "pm-27060-password-prelogin-from-sdk",
        clients: &[ClientKind::Android, ClientKind::Browser],
        reason: "the SDK asks how a master key is derived",
    },
    FlagRule {
        key: "pm-30110-sdk-sends-api",
        clients: &[ClientKind::Browser],
        reason: "the SDK makes the requests for Sends",
    },
    FlagRule {
        key: "pm-27278-v2-password-registration",
        clients: &[ClientKind::Android, ClientKind::Browser],
        reason: "the SDK registers accounts, with other keys",
    },
    FlagRule {
        key: "force-upgrade-v2-encryption",
        clients: &[ClientKind::Browser],
        reason: "the keys of an account are replaced by other ones",
    },
    FlagRule {
        key: "pm-12241-private-key-regeneration",
        clients: &[ClientKind::Browser],
        reason: "the key pair of an account is made again",
    },
];

/// Does what the Bitwarden server does for a single user, on top of a vault folder: it registers
/// and authenticates accounts, and stores their encrypted items, folders and attachments.
///
/// Like the server it never sees anything unencrypted. Features that are about other people,
/// such as organizations and Sends, are not available.
pub struct LocalServer<F, P> {
    pub(crate) store: LocalVaultStore<F>,
    pub(crate) platform: P,
    pub(crate) client: ClientKind,
    state: Mutex<State>,
}

/// What the local server remembers between requests.
#[derive(Debug, Default)]
pub(crate) struct State {
    /// The `sync` part of each vault as of the last time it was returned in full.
    pub(crate) synced_vaults: HashMap<String, Value>,
    /// When the file of this device was last looked at for what it no longer has to hold, for
    /// each account.
    tidied: HashMap<String, i64>,
}

/// Why a request was not answered.
#[derive(Debug)]
pub(crate) enum Failure {
    /// The vault folder could not be reached.
    Io(IoError),
    /// The body of the request is not what the request needs it to be.
    InvalidRequest,
}

impl From<IoError> for Failure {
    fn from(error: IoError) -> Self {
        Self::Io(error)
    }
}

impl From<InvalidRequest> for Failure {
    fn from(_: InvalidRequest) -> Self {
        Self::InvalidRequest
    }
}

/// What a handler of a request comes to.
pub(crate) type Outcome = Result<LocalResponse, Failure>;

/// What answers a request that is made without an account.
enum PublicRoute {
    Token,
    PreLogin,
    SendVerificationEmail,
    VerificationEmailClicked,
    RegisterFinish,
    PasswordHint,
    Config,
    KnownDevice,
    Collect,
    AttachmentContent,
}

/// What answers a request that is made as an account, once the account is known. It borrows the
/// IDs from the path of the request.
enum AccountRoute<'a> {
    Sync,
    RevisionDate,
    CreateCipher,
    CreateCipherWithCollections,
    ImportCiphers,
    Purge,
    DeleteCiphers,
    SoftDeleteCiphers,
    RestoreCiphers,
    ArchiveCiphers(bool),
    MoveCiphers,
    GetCipher(&'a str),
    UpdateCipher(&'a str),
    UpdateCipherPartially(&'a str),
    DeleteCipher(&'a str),
    SoftDeleteCipher(&'a str),
    RestoreCipher(&'a str),
    ArchiveCipher(&'a str, bool),
    CreateAttachment(&'a str),
    RenewAttachment(&'a str, &'a str),
    GetAttachment(&'a str, &'a str),
    DeleteAttachment(&'a str, &'a str),
    CreateFolder,
    DeleteFolders,
    DeleteAllFolders,
    GetFolder(&'a str),
    UpdateFolder(&'a str),
    DeleteFolder(&'a str),
    Profile,
    VerifyPassword,
    ChangePassword,
    UpdateKdf,
    RecordUserKeyId,
    RotateUserAccountKeys,
    DeleteAccount,
    LocalVaultDevices,
    RetireLocalVaultDevice(&'a str),
    /// A request that there is nothing to do for, which is answered with this value.
    Constant(Value),
    /// A request for a list that is always empty here.
    EmptyList,
    /// A request that there is nothing to do for, which is answered without a body.
    Empty,
}

impl AccountRoute<'_> {
    /// What of the vault the response has, which tells what is left out of it (see `withheld`).
    /// Every route is named, so that a route cannot be added without saying it.
    fn returned(&self) -> Returned {
        use AccountRoute as R;
        match self {
            R::Sync => Returned::Vault,
            R::Profile => Returned::Profile,
            R::CreateCipher
            | R::CreateCipherWithCollections
            | R::GetCipher(_)
            | R::UpdateCipher(_)
            | R::UpdateCipherPartially(_)
            | R::RestoreCipher(_)
            | R::ArchiveCipher(..) => Returned::Cipher,
            R::RestoreCiphers | R::ArchiveCiphers(_) => Returned::Ciphers,
            R::CreateAttachment(_) | R::RenewAttachment(..) => {
                Returned::CipherUnder("cipherResponse")
            }
            R::DeleteAttachment(..) => Returned::CipherUnder("cipher"),
            // Folders, attachments and devices, which a client reads nothing of organizations
            // or domains from, or nothing of the vault at all.
            R::GetAttachment(..)
            | R::CreateFolder
            | R::GetFolder(_)
            | R::UpdateFolder(_)
            | R::LocalVaultDevices
            | R::RevisionDate
            | R::ImportCiphers
            | R::Purge
            | R::DeleteCiphers
            | R::SoftDeleteCiphers
            | R::MoveCiphers
            | R::DeleteCipher(_)
            | R::SoftDeleteCipher(_)
            | R::DeleteFolders
            | R::DeleteAllFolders
            | R::DeleteFolder(_)
            | R::VerifyPassword
            | R::ChangePassword
            | R::UpdateKdf
            | R::RecordUserKeyId
            | R::RotateUserAccountKeys
            | R::DeleteAccount
            | R::RetireLocalVaultDevice(_)
            | R::Constant(_)
            | R::EmptyList
            | R::Empty => Returned::Nothing,
        }
    }
}

impl<F: FileSystem, P: Platform> LocalServer<F, P> {
    /// A local server on the vault folder that the file system reaches, for the device with the
    /// ID, the name and the type.
    ///
    /// The ID is that of this installation of the client, such as the UUID that it identifies
    /// itself to a Bitwarden server with, and is the same every time. It names the directory
    /// that the device writes its changes to, which no other device writes: it is made of 1 to
    /// 128 ASCII letters, digits, `-` and `_`. Fails for any other ID, as the local server could
    /// write nothing with it: every request that changes the vault would fail.
    ///
    /// The name and the type are what the client names the device to a Bitwarden server as it
    /// logs in (`deviceName` and `deviceType`): the model of a phone, or the browser that an
    /// extension is in, and the number of the kind of the device in the Bitwarden API
    /// (`DeviceType`). The files of the device say them, so that the devices that share the vault
    /// folder can be told apart.
    pub fn new(
        file_system: F,
        platform: P,
        client: ClientKind,
        device_id: &str,
        device_name: &str,
        device_type: i64,
    ) -> Result<Self, IoError> {
        if !is_safe_segment(device_id) {
            return Err(IoError::new(DEVICE_ID_MESSAGE));
        }
        let description = DeviceDescription {
            name: device_name.to_owned(),
            device_type,
        };
        Ok(Self {
            store: LocalVaultStore::new(file_system, device_id, description),
            platform,
            client,
            state: Mutex::new(State::default()),
        })
    }

    /// The file system that the vault folder is reached through.
    pub fn file_system(&self) -> &F {
        self.store.file_system()
    }

    /// Answers a request the way the Bitwarden server would.
    ///
    /// Requests are handled one at a time, as each of them reads the whole vault and then writes
    /// what changed in it: a request that comes while another one is handled waits for it.
    ///
    /// Fails only if the vault folder cannot be reached, which a client reports as a request
    /// that did not reach its server. Every other failure is a response, in the format that the
    /// Bitwarden API reports errors in.
    pub async fn handle(&self, request: &LocalRequest) -> Result<LocalResponse, IoError> {
        let mut state = self.state.lock().await;
        self.handle_locked(request, &mut state).await
    }

    /// Answers a request, and does what the response says with the content of an attachment
    /// before the next request is handled: stores the body of the request where the response
    /// says, and reads the file whose content is the body of the response, which it returns
    /// along with the response.
    ///
    /// It is for a client that has the content of an attachment in memory anyway. Fails if the
    /// vault folder cannot be reached, which a file of a response that is gone is taken for.
    pub(crate) async fn handle_with_content(
        &self,
        request: &LocalRequest,
    ) -> Result<(LocalResponse, Option<Vec<u8>>), IoError> {
        let mut state = self.state.lock().await;
        let response = self.handle_locked(request, &mut state).await?;
        let fs = self.file_system();
        if let Some(path) = &response.store_request_body_at {
            fs.write(&as_strs(path), &request.body).await?;
        }
        let content = match &response.body {
            ResponseBody::File(path) => {
                let gone = || IoError::new(ATTACHMENT_GONE_MESSAGE);
                Some(fs.read(&as_strs(path)).await?.ok_or_else(gone)?)
            }
            _ => None,
        };
        Ok((response, content))
    }

    async fn handle_locked(
        &self,
        request: &LocalRequest,
        state: &mut State,
    ) -> Result<LocalResponse, IoError> {
        match self.route(request, state).await {
            Ok(response) => Ok(response),
            Err(Failure::InvalidRequest) => Ok(invalid_request_response()),
            Err(Failure::Io(error)) => Err(error),
        }
    }

    async fn route(&self, request: &LocalRequest, state: &mut State) -> Outcome {
        use PublicRoute as R;
        let path: Vec<&str> = request.path.iter().map(String::as_str).collect();
        let Some(route) = public_route(&request.method, &path) else {
            return self.route_authenticated(request, &path, state).await;
        };
        match route {
            R::Token => self.token(request).await,
            R::PreLogin => self.pre_login(request).await,
            R::SendVerificationEmail => self.send_verification_email(request).await,
            R::VerificationEmailClicked => Ok(ok_empty_response()),
            R::RegisterFinish => self.register_finish(request).await,
            R::PasswordHint => self.password_hint(request).await,
            R::Config => Ok(ok_response(&config())),
            R::KnownDevice => Ok(ok_response(&Value::Bool(false))),
            R::Collect => Ok(ok_empty_response()),
            R::AttachmentContent => self.attachment_content(request).await,
        }
    }

    /// Answers a request that is made as an account. Whether there is a route for it is looked
    /// at before whose it is: a request that there is no route for is refused as one, with or
    /// without the token of an account, and never as one that is not authorized.
    ///
    /// A token that was issued before the user key of the account was rotated is not authorized:
    /// the client still has the key before, which the vault no longer has, and would encrypt with
    /// it. Refused, it logs the account out, to be logged in to with the master password that
    /// unlocks the new one (see `rotation`).
    async fn route_authenticated(
        &self,
        request: &LocalRequest,
        path: &[&str],
        state: &mut State,
    ) -> Outcome {
        let Some(route) = account_route(&request.method, path) else {
            // What shows a request that an update of a client or of the SDK started to make.
            let message = format!("Local server refused: {} {}", request.method, logged(path));
            self.platform.log(LogLevel::Warning, &message);
            return Ok(unsupported_response());
        };
        let bearer = request
            .access_token
            .as_deref()
            .and_then(bearer_of_access_token);
        let Some(bearer) = bearer else {
            return Ok(unauthorized_response());
        };
        let Some(vault) = self.read_vault(&bearer.user_id).await? else {
            return Ok(unauthorized_response());
        };
        if bearer.user_key != user_key_rotation(&vault) {
            return Ok(unauthorized_response());
        }
        let returned = route.returned();
        let response = self
            .run(route, &bearer.user_id, &vault, request, state)
            .await?;
        // The one place where what a file says about organizations and domains is left out of
        // what a client is told (see `withheld`).
        Ok(withhold(returned, response))
    }

    async fn run(
        &self,
        route: AccountRoute<'_>,
        user_id: &str,
        vault: &ReadVault,
        request: &LocalRequest,
        state: &mut State,
    ) -> Outcome {
        use AccountRoute as R;
        match route {
            R::Sync => {
                self.tidy(user_id, state).await;
                Ok(self.sync(user_id, vault, state))
            }
            R::RevisionDate => Ok(self.revision_date(user_id, vault, state)),
            R::CreateCipher => self.create_cipher(user_id, vault, request).await,
            R::CreateCipherWithCollections => {
                self.create_cipher_with_collections(user_id, vault, request)
                    .await
            }
            R::ImportCiphers => self.import_ciphers(user_id, vault, request).await,
            R::Purge => self.purge(user_id, vault, request).await,
            R::DeleteCiphers => self.delete_ciphers(user_id, vault, request).await,
            R::SoftDeleteCiphers => self.soft_delete_ciphers(user_id, vault, request).await,
            R::RestoreCiphers => self.restore_ciphers(user_id, vault, request).await,
            R::ArchiveCiphers(archived) => {
                self.archive_ciphers(user_id, vault, request, archived)
                    .await
            }
            R::MoveCiphers => self.move_ciphers(user_id, vault, request).await,
            R::GetCipher(id) => Ok(get_cipher(vault, id)),
            R::UpdateCipher(id) => self.update_cipher(user_id, vault, id, request).await,
            R::UpdateCipherPartially(id) => {
                self.update_cipher_partially(user_id, vault, id, request)
                    .await
            }
            R::DeleteCipher(id) => self.delete_cipher(user_id, vault, id).await,
            R::SoftDeleteCipher(id) => self.soft_delete_cipher(user_id, vault, id).await,
            R::RestoreCipher(id) => self.restore_cipher(user_id, vault, id).await,
            R::ArchiveCipher(id, archived) => {
                self.archive_cipher(user_id, vault, id, archived).await
            }
            R::CreateAttachment(id) => self.create_attachment(user_id, vault, id, request).await,
            R::RenewAttachment(id, attachment_id) => {
                Ok(renew_attachment(user_id, vault, id, attachment_id))
            }
            R::GetAttachment(id, attachment_id) => {
                Ok(get_attachment(user_id, vault, id, attachment_id))
            }
            R::DeleteAttachment(id, attachment_id) => {
                self.delete_attachment(user_id, vault, id, attachment_id)
                    .await
            }
            R::CreateFolder => self.create_folder(user_id, vault, request).await,
            R::DeleteFolders => self.delete_folders(user_id, vault, request).await,
            R::DeleteAllFolders => self.delete_all_folders(user_id, vault).await,
            R::GetFolder(id) => Ok(get_folder(vault, id)),
            R::UpdateFolder(id) => self.update_folder(user_id, vault, id, request).await,
            R::DeleteFolder(id) => self.delete_folder(user_id, vault, id).await,
            R::Profile => Ok(ok_response(&Value::Object(profile(vault)))),
            R::VerifyPassword => verify_password(vault, request),
            R::ChangePassword => self.change_password(user_id, vault, request).await,
            R::UpdateKdf => self.update_kdf(user_id, vault, request).await,
            R::RecordUserKeyId => self.record_user_key_id(user_id, vault, request).await,
            R::RotateUserAccountKeys => {
                self.rotate_user_account_keys(user_id, vault, request).await
            }
            R::DeleteAccount => self.delete_account(user_id, vault, request).await,
            R::LocalVaultDevices => self.local_vault_devices(user_id).await,
            R::RetireLocalVaultDevice(device_id) => {
                self.retire_local_vault_device(user_id, device_id).await
            }
            R::Constant(value) => Ok(ok_response(&value)),
            R::EmptyList => Ok(list_response(Vec::new())),
            R::Empty => Ok(ok_empty_response()),
        }
    }

    /// The current time, the way dates are stored in the vault.
    pub(crate) fn now(&self) -> String {
        format_date(self.platform.now_millis())
    }

    /// A new random ID.
    pub(crate) fn new_id(&self) -> String {
        new_uuid(&self.platform)
    }

    /// Writes the change of the vault of the account from the vault that was read to the vault
    /// that is given, which it comes to as of now.
    pub(crate) async fn save(
        &self,
        user_id: &str,
        read: &ReadVault,
        vault: &JsonObject,
    ) -> Result<(), IoError> {
        let now = self.platform.now_millis();
        let vault = with_fields(
            vault,
            [(KEY_REVISION_DATE, Value::String(format_date(now)))],
        );
        self.store.write_vault(user_id, read, &vault, now).await
    }

    /// Leaves out of the file of this device what it no longer has to hold for the account, and
    /// deletes the content of the attachments that it removed once nothing can bring them back,
    /// once a day at most. It is done when the client syncs, which is when the changes of other
    /// devices come in. A failure is only logged, as the vault is the same either way, and is
    /// tried again at the next sync: this is also what leaves a master password that another
    /// device replaced out of the file.
    async fn tidy(&self, user_id: &str, state: &mut State) {
        let now = self.platform.now_millis();
        let last = state.tidied.get(user_id).copied();
        if last.is_some_and(|last| now.saturating_sub(last) < TIDY_INTERVAL_MILLIS) {
            return;
        }
        if self.store.tidy(user_id, now).await.is_ok() {
            state.tidied.insert(user_id.to_owned(), now);
        } else {
            self.platform.log(LogLevel::Warning, TIDY_FAILED_MESSAGE);
        }
    }

    /// Returns the vault of the account with the email, the first one if there are several,
    /// without its folders and items (see [`Self::find_accounts`]).
    pub(crate) async fn first_vault_of(&self, email: &str) -> Result<Option<JsonObject>, IoError> {
        let accounts = self.find_accounts(email).await?;
        Ok(accounts.into_iter().next().map(|(_, vault)| vault))
    }

    /// Returns the vault of the account, which a change of it is written against, or `None` if
    /// the account is not there (see [`LocalVaultStore::read_vault`]).
    pub(crate) async fn read_vault(&self, user_id: &str) -> Result<Option<ReadVault>, IoError> {
        self.reported(self.store.read_vault(user_id).await)
    }

    /// Returns the vault of the account without its folders and items, or `None` if the account
    /// is not there (see [`LocalVaultStore::read_account`]).
    pub(crate) async fn read_account(&self, user_id: &str) -> Result<Option<JsonObject>, IoError> {
        self.reported(self.store.read_account(user_id).await)
    }

    /// Returns the accounts with the email by their IDs, each with its vault without its folders
    /// and items, which a request that looks for an account by its email does not need (see
    /// [`LocalVaultStore::find_accounts`]).
    pub(crate) async fn find_accounts(
        &self,
        email: &str,
    ) -> Result<Vec<(String, JsonObject)>, IoError> {
        self.reported(self.store.find_accounts(email).await)
    }

    /// What a request fails with when the vault of an account, or the account with an email,
    /// could not be read. A client only reports it as a request that did not reach its server,
    /// so an account whose vault cannot be used for now is logged with its ID, which is the name
    /// of its directory in the vault folder: the files of an account can keep from coming for
    /// good, and the directory then has to be found to be deleted by hand.
    pub(crate) fn reported<T>(&self, read: Result<T, ReadError>) -> Result<T, IoError> {
        read.map_err(|error| match error {
            ReadError::Io(error) => error,
            ReadError::Unusable(account_id, why) => {
                let reason = why.message();
                let message = format!("Local server cannot use account {account_id}: {reason}");
                self.platform.log(LogLevel::Warning, &message);
                IoError::new(reason)
            }
        })
    }
}

/// Returns `true` if the local server answers the request, and does not refuse it as a feature
/// that needs a Bitwarden server. The path is relative to the service that the request is for,
/// and has a UUID wherever the ID of an item or a folder goes. Whether the request succeeds
/// depends on what it asks for and on whose request it is.
///
/// It is what a client checks the requests that it can make against, so that the route table
/// is only here.
pub fn is_answered(method: &str, path: &[&str]) -> bool {
    public_route(method, path).is_some() || account_route(method, path).is_some()
}

/// Returns what answers a request that is made without an account, or `None` if it is not one
/// of those. The content of an attachment is reached by its address alone, as that of cloud
/// storage is.
fn public_route(method: &str, path: &[&str]) -> Option<PublicRoute> {
    use PublicRoute as R;
    let route = match (method, path) {
        ("POST", ["connect", "token"]) => R::Token,
        ("POST", ["accounts", "prelogin"] | ["accounts", "prelogin", "password"]) => R::PreLogin,
        ("POST", ["accounts", "register", "send-verification-email"]) => R::SendVerificationEmail,
        ("POST", ["accounts", "register", "verification-email-clicked"]) => {
            R::VerificationEmailClicked
        }
        ("POST", ["accounts", "register", "finish"]) => R::RegisterFinish,
        ("POST", ["accounts", "password-hint"]) => R::PasswordHint,
        ("GET", ["config"]) => R::Config,
        ("GET", ["devices", "knowndevice"]) => R::KnownDevice,
        ("POST", ["collect"]) => R::Collect,
        ("GET" | "PUT", [ATTACHMENTS_PATH, ..]) => R::AttachmentContent,
        _ => return None,
    };
    Some(route)
}

/// Returns what answers a request that is made as an account, or `None` if there is no route
/// for it. An item or a folder is only taken to be named in a path by a UUID, which keeps
/// requests such as `DELETE ciphers/admin` from being taken for one.
///
/// The paths under `local-vault` are those of what only the clients of the local vault ask for,
/// which a Bitwarden server does not have: the devices that share the vault folder.
fn account_route<'a>(method: &str, path: &[&'a str]) -> Option<AccountRoute<'a>> {
    use AccountRoute as R;
    let route = match (method, path) {
        ("GET", ["sync"]) => R::Sync,
        ("GET", ["accounts", "revision-date"]) => R::RevisionDate,
        ("POST", ["ciphers"]) => R::CreateCipher,
        ("POST", ["ciphers", "create"]) => R::CreateCipherWithCollections,
        ("POST", ["ciphers", "import"]) => R::ImportCiphers,
        ("POST", ["ciphers", "purge"]) => R::Purge,
        ("GET", ["ciphers", "has-unassigned-ciphers"]) => R::Constant(Value::Bool(false)),
        ("DELETE", ["ciphers"]) => R::DeleteCiphers,
        ("PUT", ["ciphers", "delete"]) => R::SoftDeleteCiphers,
        ("PUT", ["ciphers", "restore"]) => R::RestoreCiphers,
        ("PUT", ["ciphers", "archive"]) => R::ArchiveCiphers(true),
        ("PUT", ["ciphers", "unarchive"]) => R::ArchiveCiphers(false),
        ("PUT", ["ciphers", "move"]) => R::MoveCiphers,
        ("GET", ["ciphers", id] | ["ciphers", id, "details"]) if is_uuid(id) => R::GetCipher(id),
        ("PUT", ["ciphers", id]) if is_uuid(id) => R::UpdateCipher(id),
        ("PUT", ["ciphers", id, "partial"]) if is_uuid(id) => R::UpdateCipherPartially(id),
        ("DELETE", ["ciphers", id]) if is_uuid(id) => R::DeleteCipher(id),
        ("PUT", ["ciphers", id, "delete"]) if is_uuid(id) => R::SoftDeleteCipher(id),
        ("PUT", ["ciphers", id, "restore"]) if is_uuid(id) => R::RestoreCipher(id),
        ("PUT", ["ciphers", id, "archive"]) if is_uuid(id) => R::ArchiveCipher(id, true),
        ("PUT", ["ciphers", id, "unarchive"]) if is_uuid(id) => R::ArchiveCipher(id, false),
        ("POST", ["ciphers", id, "attachment", "v2"]) if is_uuid(id) => R::CreateAttachment(id),
        ("GET", ["ciphers", id, "attachment", attachment_id, "renew"]) if is_uuid(id) => {
            R::RenewAttachment(id, attachment_id)
        }
        ("GET", ["ciphers", id, "attachment", attachment_id]) if is_uuid(id) => {
            R::GetAttachment(id, attachment_id)
        }
        ("DELETE", ["ciphers", id, "attachment", attachment_id]) if is_uuid(id) => {
            R::DeleteAttachment(id, attachment_id)
        }
        ("POST", ["folders"]) => R::CreateFolder,
        ("DELETE", ["folders"]) => R::DeleteFolders,
        ("DELETE", ["folders", "all"]) => R::DeleteAllFolders,
        ("GET", ["folders", id]) if is_uuid(id) => R::GetFolder(id),
        ("PUT", ["folders", id]) if is_uuid(id) => R::UpdateFolder(id),
        ("DELETE", ["folders", id]) if is_uuid(id) => R::DeleteFolder(id),
        ("GET", ["accounts", "profile"]) => R::Profile,
        ("POST", ["accounts", "verify-password"]) => R::VerifyPassword,
        ("POST", ["accounts", "password"]) => R::ChangePassword,
        ("POST", ["accounts", "kdf"]) => R::UpdateKdf,
        ("POST", ["accounts", "key-management", "user-key-id"]) => R::RecordUserKeyId,
        ("POST", ["accounts", "key-management", "rotate-user-account-keys"]) => {
            R::RotateUserAccountKeys
        }
        ("DELETE", ["accounts"]) => R::DeleteAccount,
        ("GET", ["local-vault", "devices"]) => R::LocalVaultDevices,
        ("POST", ["local-vault", "devices", device_id, "retire"]) => {
            R::RetireLocalVaultDevice(device_id)
        }
        ("GET", ["auth-requests"]) => R::EmptyList,
        ("GET", ["auth-requests", "pending"]) => R::EmptyList,
        ("GET", ["devices"]) => R::EmptyList,
        ("GET", ["tasks"]) => R::EmptyList,
        ("GET", ["notifications"]) => R::EmptyList,
        ("PUT", ["devices", "identifier", _, "token"]) => R::Empty,
        _ => return None,
    };
    Some(route)
}

/// Returns the path the way it is logged: with a `*` in place of every segment that is not a
/// word of the API, so that the log does not tell whose request it was or what it was about.
fn logged(path: &[&str]) -> String {
    path.iter()
        .map(|segment| if is_api_word(segment) { *segment } else { "*" })
        .collect::<Vec<_>>()
        .join("/")
}

/// Returns `true` if the segment of a path is a word of the API: lower case letters, with
/// hyphens between them, and maybe a digit at the end, such as `v2`.
fn is_api_word(segment: &str) -> bool {
    let [first, middle @ .., last] = segment.as_bytes() else {
        return false;
    };
    first.is_ascii_lowercase()
        && middle.iter().all(|b| b.is_ascii_lowercase() || *b == b'-')
        && (last.is_ascii_lowercase() || last.is_ascii_digit())
}

/// No feature flags are reported, which keeps a client on the code paths that go through the
/// local server instead of the ones where the SDK talks to a server by itself.
fn config() -> Value {
    json!({
        "object": "config",
        "version": SERVER_VERSION,
        "gitHash": "local",
        "server": null,
        "environment": {},
        "featureStates": {},
        "settings": {"disableUserRegistration": false},
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_is_logged_without_what_identifies_an_item() {
        let id = "11111111-2222-4333-8444-555555555555";

        let refused = ["sends", "user@example.com", "a", "B", "2fa"];
        let options = ["accounts", "webauthn", "assertion-options"];

        assert_eq!(logged(&["ciphers", id, "share"]), "ciphers/*/share");
        assert_eq!(logged(&["ciphers", id, "v2"]), "ciphers/*/v2");
        assert_eq!(logged(&options), "accounts/webauthn/assertion-options");
        assert_eq!(logged(&refused), "sends/*/*/*/*");
    }
}
