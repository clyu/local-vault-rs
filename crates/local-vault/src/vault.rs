//! What the Bitwarden API does for the content of a vault: its items, folders and attachments.
//! Everything is stored the way the server returns it when a client syncs.

use serde_json::{Value, json};

use crate::account::{is_password_hash, recorded_user_key_id};
use crate::date::{parse_date_millis, parse_date_nanos};
use crate::fs::{FileSystem, IoError};
use crate::http::{
    HTTP_CREATED, LocalRequest, LocalResponse, bad_request, empty_response, file_response,
    invalid_request_response, list_response, not_found_response, ok_empty_response, ok_response,
    unsupported_response,
};
use crate::json::{
    JsonObject, element, eq_ignore_case, int, into_object, obj, objects, string, strings, text,
    with_fields, without_fields,
};
use crate::organizations::{cipher_without_organization, sync_without_organizations};
use crate::platform::Platform;
use crate::server::{LocalServer, Outcome, State};
use crate::store::{KEY_REVISION_DATE, KEY_SYNC, ReadVault};

/// The host of the addresses that the local server hands out for the content of attachments,
/// and of the addresses that a client has in place of those of a server. It is reserved, so it
/// can never resolve to a real server.
pub const LOCAL_VAULT_HOST: &str = "vault.local.invalid";

/// The first segment of the path that the content of attachments is served under.
pub const ATTACHMENTS_PATH: &str = "attachments";

const CIPHERS: &str = "ciphers";
const FOLDERS: &str = "folders";
const FILE_UPLOAD_TYPE_AZURE: i64 = 1;
const BYTES_PER_KB: u64 = 1024;
const BYTES_PER_MB: u64 = 1024 * 1024;

/// How far the revision date that a client knows an item by may be from the one in the vault, in
/// nanoseconds. The same allowance the server makes, for dates that lose precision on their way.
const OUT_OF_DATE_TOLERANCE_NANOS: i128 = 1_000_000_000;

/// What a request for an item has that is about the request and not about the item.
const REQUEST_FIELDS: [&str; 4] = [
    "lastKnownRevisionDate",
    "attachments2",
    "encryptedFor",
    "encryptedByKeyId",
];

const OUT_OF_DATE_MESSAGE: &str =
    "The item you are updating is out of date. Sync your vault and try again.";
const UPLOAD_IN_BLOCKS_MESSAGE: &str =
    "An attachment of this size cannot be kept in a local vault.";
const ENCRYPTED_FOR_ANOTHER_MESSAGE: &str =
    "The item was not encrypted for the account that it is saved to. Try again.";
const ENCRYPTED_BY_ANOTHER_KEY_MESSAGE: &str =
    "The item was not encrypted with the user key of this account. Sync your vault and try again.";
const INVALID_PASSWORD_MESSAGE: &str = "Invalid master password.";

impl<F: FileSystem, P: Platform> LocalServer<F, P> {
    /// Returns the whole vault, without what it says about organizations, and remembers what the
    /// vault was.
    pub(crate) fn sync(
        &self,
        user_id: &str,
        vault: &JsonObject,
        state: &mut State,
    ) -> LocalResponse {
        let sync = obj(vault, KEY_SYNC).cloned().unwrap_or_default();
        let response = ok_response(&Value::Object(sync_without_organizations(&sync)));
        // As it is on disk, which the vault is compared with to tell whether it changed.
        state
            .synced_vaults
            .insert(user_id.to_owned(), Value::Object(sync));
        response
    }

    /// Returns when the vault last changed, in milliseconds since the epoch.
    ///
    /// The vault file can be replaced from outside the client, for one by a tool that syncs it
    /// with another device, and with a date that is older than the last time the client synced.
    /// So unless the vault is the one that was last returned in full, it is reported as having
    /// changed just now.
    pub(crate) fn revision_date(
        &self,
        user_id: &str,
        vault: &JsonObject,
        state: &State,
    ) -> LocalResponse {
        let sync = obj(vault, KEY_SYNC).cloned().map(Value::Object);
        let is_synced = sync.is_some() && state.synced_vaults.get(user_id) == sync.as_ref();
        let synced_millis = string(vault, KEY_REVISION_DATE)
            .filter(|_| is_synced)
            .and_then(parse_date_millis);
        let millis = synced_millis.unwrap_or_else(|| self.platform.now_millis());
        ok_response(&Value::from(millis))
    }

    /// Adds an item to the vault.
    pub(crate) async fn create_cipher(
        &self,
        user_id: &str,
        vault: &ReadVault,
        request: &LocalRequest,
    ) -> Outcome {
        self.add_cipher(user_id, vault, &request.json_body()?).await
    }

    /// Adds an item that comes with the collections of an organization to put it in. This is how
    /// a client sends an item of the user as well, which comes without collections. There are no
    /// organizations here, so the collections are left out.
    pub(crate) async fn create_cipher_with_collections(
        &self,
        user_id: &str,
        vault: &ReadVault,
        request: &LocalRequest,
    ) -> Outcome {
        match obj(&request.json_body()?, "cipher") {
            Some(body) => self.add_cipher(user_id, vault, body).await,
            None => Ok(invalid_request_response()),
        }
    }

    /// Replaces an item of the vault, unless it changed since the client last received it.
    pub(crate) async fn update_cipher(
        &self,
        user_id: &str,
        vault: &ReadVault,
        cipher_id: &str,
        request: &LocalRequest,
    ) -> Outcome {
        let Some(existing) = item(vault, CIPHERS, cipher_id) else {
            return Ok(not_found_response());
        };
        let body = request.json_body()?;
        if let Some(refusal) = refusal(&body, user_id, vault) {
            return Ok(refusal);
        }
        if is_out_of_date(&existing, string(&body, "lastKnownRevisionDate")) {
            return Ok(bad_request(OUT_OF_DATE_MESSAGE));
        }
        let id = id_of(&existing, cipher_id);
        let cipher = to_cipher(&body, &id, Some(&existing), &self.now());
        let updated = with_item(vault, CIPHERS, &cipher);
        self.save(user_id, vault, &updated).await?;
        Ok(cipher_response(&cipher))
    }

    /// Changes what an item has for the account only: the folder that it is in, and whether it
    /// is a favorite.
    pub(crate) async fn update_cipher_partially(
        &self,
        user_id: &str,
        vault: &ReadVault,
        cipher_id: &str,
        request: &LocalRequest,
    ) -> Outcome {
        let Some(existing) = item(vault, CIPHERS, cipher_id) else {
            return Ok(not_found_response());
        };
        let body = request.json_body()?;
        let folder_id = string(&body, "folderId").map_or(Value::Null, Value::from);
        let is_favorite = element(&body, "favorite") == Some(&Value::Bool(true));
        let cipher = with_fields(
            &existing,
            [
                ("folderId", folder_id),
                ("favorite", Value::Bool(is_favorite)),
                ("revisionDate", Value::String(self.now())),
            ],
        );
        let updated = with_item(vault, CIPHERS, &cipher);
        self.save(user_id, vault, &updated).await?;
        Ok(cipher_response(&cipher))
    }

    /// Puts items in a folder, or in none.
    pub(crate) async fn move_ciphers(
        &self,
        user_id: &str,
        vault: &ReadVault,
        request: &LocalRequest,
    ) -> Outcome {
        let body = request.json_body()?;
        let ids = strings(&body, "ids");
        let folder_id = string(&body, "folderId").map_or(Value::Null, Value::from);
        // The client is not sent the items, so it keeps the revision dates that it knows them by.
        let updated = with_each_item(vault, CIPHERS, &ids, |cipher| {
            with_fields(cipher, [("folderId", folder_id.clone())])
        });
        self.save(user_id, vault, &updated).await?;
        Ok(ok_empty_response())
    }

    /// Removes an item and its attachments from the vault. The content of the attachments is
    /// deleted later, once nothing can bring the item back (see `LocalVaultStore::tidy`).
    pub(crate) async fn delete_cipher(
        &self,
        user_id: &str,
        vault: &ReadVault,
        cipher_id: &str,
    ) -> Outcome {
        let Some(cipher) = item(vault, CIPHERS, cipher_id) else {
            return Ok(not_found_response());
        };
        let id = id_of(&cipher, cipher_id);
        let updated = without_items(vault, CIPHERS, std::slice::from_ref(&id));
        self.save(user_id, vault, &updated).await?;
        Ok(ok_empty_response())
    }

    /// Removes several items and their attachments from the vault, as [`Self::delete_cipher`]
    /// does.
    pub(crate) async fn delete_ciphers(
        &self,
        user_id: &str,
        vault: &ReadVault,
        request: &LocalRequest,
    ) -> Outcome {
        let ids = existing_ids(vault, CIPHERS, &strings(&request.json_body()?, "ids"));
        let updated = without_items(vault, CIPHERS, &ids);
        self.save(user_id, vault, &updated).await?;
        Ok(ok_empty_response())
    }

    /// Moves an item to the trash.
    pub(crate) async fn soft_delete_cipher(
        &self,
        user_id: &str,
        vault: &ReadVault,
        cipher_id: &str,
    ) -> Outcome {
        if item(vault, CIPHERS, cipher_id).is_none() {
            return Ok(not_found_response());
        }
        let ids = [cipher_id.to_owned()];
        self.soft_delete(user_id, vault, &ids).await
    }

    /// Moves several items to the trash.
    pub(crate) async fn soft_delete_ciphers(
        &self,
        user_id: &str,
        vault: &ReadVault,
        request: &LocalRequest,
    ) -> Outcome {
        let ids = strings(&request.json_body()?, "ids");
        self.soft_delete(user_id, vault, &ids).await
    }

    /// Moves an item out of the trash.
    pub(crate) async fn restore_cipher(
        &self,
        user_id: &str,
        vault: &ReadVault,
        cipher_id: &str,
    ) -> Outcome {
        if item(vault, CIPHERS, cipher_id).is_none() {
            return Ok(not_found_response());
        }
        let ids = [cipher_id.to_owned()];
        let restored = self.restore(user_id, vault, &ids).await?;
        Ok(first_or_not_found(restored))
    }

    /// Moves several items out of the trash.
    pub(crate) async fn restore_ciphers(
        &self,
        user_id: &str,
        vault: &ReadVault,
        request: &LocalRequest,
    ) -> Outcome {
        let ids = strings(&request.json_body()?, "ids");
        let restored = self.restore(user_id, vault, &ids).await?;
        Ok(list_of(restored))
    }

    /// Moves an item to or out of the archive.
    pub(crate) async fn archive_cipher(
        &self,
        user_id: &str,
        vault: &ReadVault,
        cipher_id: &str,
        archived: bool,
    ) -> Outcome {
        if item(vault, CIPHERS, cipher_id).is_none() {
            return Ok(not_found_response());
        }
        let ids = [cipher_id.to_owned()];
        let changed = self.archive(user_id, vault, &ids, archived).await?;
        Ok(first_or_not_found(changed))
    }

    /// Moves several items to or out of the archive.
    pub(crate) async fn archive_ciphers(
        &self,
        user_id: &str,
        vault: &ReadVault,
        request: &LocalRequest,
        archived: bool,
    ) -> Outcome {
        let ids = strings(&request.json_body()?, "ids");
        let changed = self.archive(user_id, vault, &ids, archived).await?;
        Ok(list_of(changed))
    }

    /// Adds the items and folders that the client converted from another password manager.
    pub(crate) async fn import_ciphers(
        &self,
        user_id: &str,
        vault: &ReadVault,
        request: &LocalRequest,
    ) -> Outcome {
        let body = request.json_body()?;
        let ciphers = objects(&body, CIPHERS);
        // One item that cannot be decrypted in this vault refuses all of them, so that an import
        // is never stored in part.
        if let Some(refusal) = ciphers.iter().find_map(|c| refusal(c, user_id, vault)) {
            return Ok(refusal);
        }
        let date = self.now();
        // In the order of the request, which the relationships refer to by index. A folder that
        // comes with the ID of one that the vault has is that folder, as it is, and not a new one.
        // The client sends the folder that it imports into that way.
        let mut new_folders = Vec::new();
        let mut folder_ids = Vec::new();
        for folder in objects(&body, "folders") {
            let id = string(&folder, "id");
            let existing = id.and_then(|id| item(vault, FOLDERS, id));
            let folder = match existing {
                Some(existing) => existing,
                None => {
                    let new_folder = folder_json(&self.new_id(), element(&folder, "name"), &date);
                    new_folders.push(new_folder.clone());
                    new_folder
                }
            };
            let id = folder.get("id").cloned();
            folder_ids.push(id.unwrap_or(Value::Null));
        }
        let mut folder_ids_by_cipher_index = Vec::new();
        for relationship in objects(&body, "folderRelationships") {
            let cipher_index = int(&relationship, "key");
            let folder_index = int(&relationship, "value");
            let folder_id = folder_index
                .and_then(|index| usize::try_from(index).ok())
                .and_then(|index| folder_ids.get(index));
            if let (Some(cipher_index), Some(folder_id)) = (cipher_index, folder_id) {
                folder_ids_by_cipher_index.push((cipher_index, folder_id.clone()));
            }
        }
        let mut new_ciphers = Vec::new();
        for (index, cipher) in (0_i64..).zip(&ciphers) {
            // The last relationship of an item is the one that counts.
            let folder_id = folder_ids_by_cipher_index
                .iter()
                .rev()
                .find(|(cipher_index, _)| *cipher_index == index)
                .map_or(Value::Null, |(_, folder_id)| folder_id.clone());
            let cipher = to_cipher(cipher, &self.new_id(), None, &date);
            new_ciphers.push(with_fields(&cipher, [("folderId", folder_id)]));
        }
        let all_folders = [items(vault, FOLDERS), new_folders].concat();
        let all_ciphers = [items(vault, CIPHERS), new_ciphers].concat();
        let updated = with_items(vault, FOLDERS, all_folders);
        let updated = with_items(&updated, CIPHERS, all_ciphers);
        self.save(user_id, vault, &updated).await?;
        Ok(ok_empty_response())
    }

    /// Removes every item and folder from the vault, along with the attachments, as
    /// [`Self::delete_cipher`] does. Only those that the vault has here are removed: an item that
    /// another device added, and whose file has not come yet, stays, and so does the content of
    /// its attachments.
    pub(crate) async fn purge(
        &self,
        user_id: &str,
        vault: &ReadVault,
        request: &LocalRequest,
    ) -> Outcome {
        let body = request.json_body()?;
        if !is_password_hash(vault, string(&body, "masterPasswordHash")) {
            return Ok(bad_request(INVALID_PASSWORD_MESSAGE));
        }
        let empty = with_items(&with_items(vault, CIPHERS, Vec::new()), FOLDERS, Vec::new());
        self.save(user_id, vault, &empty).await?;
        Ok(ok_empty_response())
    }

    /// Adds an attachment to an item and tells the client where to send its encrypted content.
    /// The client is told to send it the way it sends it to cloud storage, which is a plain
    /// upload that can be written to the vault folder as it comes in.
    pub(crate) async fn create_attachment(
        &self,
        user_id: &str,
        vault: &ReadVault,
        cipher_id: &str,
        request: &LocalRequest,
    ) -> Outcome {
        let Some(cipher) = item(vault, CIPHERS, cipher_id) else {
            return Ok(not_found_response());
        };
        let body = request.json_body()?;
        let attachment_id = self.new_id().replace('-', "");
        let size = text(&body, "fileSize")
            .and_then(|size| size.parse::<u64>().ok())
            .unwrap_or(0);
        let attachment = json!({
            "id": attachment_id,
            "url": null,
            "fileName": element(&body, "fileName").cloned().unwrap_or(Value::Null),
            "key": element(&body, "key").cloned().unwrap_or(Value::Null),
            "size": size.to_string(),
            "sizeName": size_name(size),
            "object": "attachment",
        });
        let mut attachments: Vec<Value> = objects(&cipher, "attachments")
            .into_iter()
            .map(Value::Object)
            .collect();
        attachments.push(attachment);
        let updated_cipher = with_fields(
            &cipher,
            [
                ("attachments", Value::Array(attachments)),
                ("revisionDate", Value::String(self.now())),
            ],
        );
        let updated = with_item(vault, CIPHERS, &updated_cipher);
        self.save(user_id, vault, &updated).await?;
        let id = id_of(&cipher, cipher_id);
        let response = upload_response(user_id, &id, updated_cipher, &attachment_id);
        Ok(response)
    }

    /// Removes an attachment from an item. Its encrypted content is deleted later, once nothing
    /// can bring the attachment back (see `LocalVaultStore::tidy`).
    pub(crate) async fn delete_attachment(
        &self,
        user_id: &str,
        vault: &ReadVault,
        cipher_id: &str,
        attachment_id: &str,
    ) -> Outcome {
        let Some((cipher, _)) = cipher_and_attachment(vault, cipher_id, attachment_id) else {
            return Ok(not_found_response());
        };
        let attachments: Vec<JsonObject> = objects(&cipher, "attachments")
            .into_iter()
            .filter(|attachment| !has_id(attachment, attachment_id))
            .collect();
        // The revision date stays, as a client that is not sent the item, as the Android app,
        // keeps the one that it knows the item by. A client that reads the item from the
        // response finds the same one.
        let updated_cipher = with_fields(&cipher, [("attachments", array_or_null(attachments))]);
        let updated = with_item(vault, CIPHERS, &updated_cipher);
        self.save(user_id, vault, &updated).await?;
        let cipher = cipher_without_organization(&updated_cipher);
        Ok(ok_response(&json!({"cipher": cipher})))
    }

    /// Stores or returns the encrypted content of an attachment, at the address that
    /// [`Self::create_attachment`] and [`get_attachment`] hand out. A request for it comes
    /// without the token of an account, as one for cloud storage would.
    pub(crate) async fn attachment_content(&self, request: &LocalRequest) -> Outcome {
        let [_, user_id, cipher_id, attachment_id] = request.path.as_slice() else {
            return Ok(not_found_response());
        };
        match request.method.as_str() {
            "PUT" => {
                // A client sends a file that is too large for a single request in blocks, and
                // then the list of those blocks, and says so in the query of each of these
                // requests. They are not put together here, and none of them is the content.
                if request.query.contains_key("comp") {
                    return Ok(bad_request(UPLOAD_IN_BLOCKS_MESSAGE));
                }
                let ids = self.listed_attachment(user_id, cipher_id, attachment_id);
                let Some((id, attachment_id)) = ids.await? else {
                    return Ok(not_found_response());
                };
                let Some(path) = self.store.attachment_path(user_id, &id, &attachment_id) else {
                    return Err(IoError::new("Invalid attachment path").into());
                };
                let mut response = empty_response(HTTP_CREATED);
                response.store_request_body_at = Some(path);
                Ok(response)
            }
            "GET" => {
                // The content of an attachment that was removed is kept for a while, as a change
                // of another device can bring the attachment back, but it is not handed out.
                let ids = self.listed_attachment(user_id, cipher_id, attachment_id);
                let Some((id, attachment_id)) = ids.await? else {
                    return Ok(not_found_response());
                };
                let attachment = self.store.attachment(user_id, &id, &attachment_id);
                match attachment.await? {
                    Some(path) => Ok(file_response(path)),
                    None => Ok(not_found_response()),
                }
            }
            _ => Ok(unsupported_response()),
        }
    }

    /// Returns the IDs that the vault of the account has an attachment of an item under, or
    /// `None` if it does not have the attachment.
    async fn listed_attachment(
        &self,
        user_id: &str,
        cipher_id: &str,
        attachment_id: &str,
    ) -> Result<Option<(String, String)>, IoError> {
        let Some(vault) = self.read_vault(user_id).await? else {
            return Ok(None);
        };
        let found = cipher_and_attachment(&vault, cipher_id, attachment_id);
        Ok(found.map(|(cipher, attachment)| {
            (id_of(&cipher, cipher_id), id_of(&attachment, attachment_id))
        }))
    }

    /// Adds a folder to the vault.
    pub(crate) async fn create_folder(
        &self,
        user_id: &str,
        vault: &ReadVault,
        request: &LocalRequest,
    ) -> Outcome {
        let body = request.json_body()?;
        let folder = folder_json(&self.new_id(), element(&body, "name"), &self.now());
        let updated = with_item(vault, FOLDERS, &folder);
        self.save(user_id, vault, &updated).await?;
        Ok(ok_response(&Value::Object(folder)))
    }

    /// Renames a folder of the vault.
    pub(crate) async fn update_folder(
        &self,
        user_id: &str,
        vault: &ReadVault,
        folder_id: &str,
        request: &LocalRequest,
    ) -> Outcome {
        let Some(existing) = item(vault, FOLDERS, folder_id) else {
            return Ok(not_found_response());
        };
        let body = request.json_body()?;
        let id = id_of(&existing, folder_id);
        let folder = folder_json(&id, element(&body, "name"), &self.now());
        let updated = with_item(vault, FOLDERS, &folder);
        self.save(user_id, vault, &updated).await?;
        Ok(ok_response(&Value::Object(folder)))
    }

    /// Removes a folder from the vault. The items in it are kept, without a folder.
    pub(crate) async fn delete_folder(
        &self,
        user_id: &str,
        vault: &ReadVault,
        folder_id: &str,
    ) -> Outcome {
        let Some(folder) = item(vault, FOLDERS, folder_id) else {
            return Ok(not_found_response());
        };
        let ids = [id_of(&folder, folder_id)];
        let updated = without_folders(vault, &ids);
        self.save(user_id, vault, &updated).await?;
        Ok(ok_empty_response())
    }

    /// Removes several folders from the vault. The items in them are kept, without a folder.
    pub(crate) async fn delete_folders(
        &self,
        user_id: &str,
        vault: &ReadVault,
        request: &LocalRequest,
    ) -> Outcome {
        let ids = existing_ids(vault, FOLDERS, &strings(&request.json_body()?, "ids"));
        let updated = without_folders(vault, &ids);
        self.save(user_id, vault, &updated).await?;
        Ok(ok_empty_response())
    }

    /// Removes every folder from the vault. The items in them are kept, without a folder.
    pub(crate) async fn delete_all_folders(&self, user_id: &str, vault: &ReadVault) -> Outcome {
        let ids: Vec<String> = items(vault, FOLDERS)
            .iter()
            .filter_map(|folder| string(folder, "id").map(str::to_owned))
            .collect();
        let updated = without_folders(vault, &ids);
        self.save(user_id, vault, &updated).await?;
        Ok(ok_empty_response())
    }

    async fn add_cipher(&self, user_id: &str, vault: &ReadVault, body: &JsonObject) -> Outcome {
        if let Some(refusal) = refusal(body, user_id, vault) {
            return Ok(refusal);
        }
        let cipher = to_cipher(body, &self.new_id(), None, &self.now());
        let updated = with_item(vault, CIPHERS, &cipher);
        self.save(user_id, vault, &updated).await?;
        Ok(cipher_response(&cipher))
    }

    async fn soft_delete(&self, user_id: &str, vault: &ReadVault, ids: &[String]) -> Outcome {
        let deleted_date = Value::String(self.now());
        // The client is not sent the items, so it keeps the revision dates that it knows them by.
        let updated = with_each_item(vault, CIPHERS, ids, |cipher| {
            with_fields(cipher, [("deletedDate", deleted_date.clone())])
        });
        self.save(user_id, vault, &updated).await?;
        Ok(ok_empty_response())
    }

    async fn restore(
        &self,
        user_id: &str,
        vault: &ReadVault,
        ids: &[String],
    ) -> Result<Vec<JsonObject>, IoError> {
        let date = Value::String(self.now());
        let updated = with_each_item(vault, CIPHERS, ids, |cipher| {
            with_fields(
                cipher,
                [("deletedDate", Value::Null), ("revisionDate", date.clone())],
            )
        });
        self.save(user_id, vault, &updated).await?;
        Ok(items_with_ids(&updated, CIPHERS, ids))
    }

    async fn archive(
        &self,
        user_id: &str,
        vault: &ReadVault,
        ids: &[String],
        archived: bool,
    ) -> Result<Vec<JsonObject>, IoError> {
        let date = Value::String(self.now());
        let archived_date = if archived { date.clone() } else { Value::Null };
        let updated = with_each_item(vault, CIPHERS, ids, |cipher| {
            with_fields(
                cipher,
                [
                    ("archivedDate", archived_date.clone()),
                    ("revisionDate", date.clone()),
                ],
            )
        });
        self.save(user_id, vault, &updated).await?;
        Ok(items_with_ids(&updated, CIPHERS, ids))
    }
}

/// Returns an item of the vault.
pub(crate) fn get_cipher(vault: &JsonObject, cipher_id: &str) -> LocalResponse {
    match item(vault, CIPHERS, cipher_id) {
        Some(cipher) => cipher_response(&cipher),
        None => not_found_response(),
    }
}

/// Returns a folder of the vault.
pub(crate) fn get_folder(vault: &JsonObject, folder_id: &str) -> LocalResponse {
    match item(vault, FOLDERS, folder_id) {
        Some(folder) => ok_response(&Value::Object(folder)),
        None => not_found_response(),
    }
}

/// Returns an attachment of an item, along with where its encrypted content is.
pub(crate) fn get_attachment(
    user_id: &str,
    vault: &JsonObject,
    cipher_id: &str,
    attachment_id: &str,
) -> LocalResponse {
    let Some((cipher, attachment)) = cipher_and_attachment(vault, cipher_id, attachment_id) else {
        return not_found_response();
    };
    let id = id_of(&cipher, cipher_id);
    let url = attachment_url(user_id, &id, &id_of(&attachment, attachment_id));
    let attachment = with_fields(&attachment, [("url", Value::String(url))]);
    ok_response(&Value::Object(attachment))
}

/// Tells the client again where to send the encrypted content of an attachment, which it asks
/// when the address that it has is about to expire. The addresses of a local vault do not, so it
/// is the same one.
pub(crate) fn renew_attachment(
    user_id: &str,
    vault: &JsonObject,
    cipher_id: &str,
    attachment_id: &str,
) -> LocalResponse {
    let Some((cipher, attachment)) = cipher_and_attachment(vault, cipher_id, attachment_id) else {
        return not_found_response();
    };
    let id = id_of(&cipher, cipher_id);
    let attachment_id = id_of(&attachment, attachment_id);
    upload_response(user_id, &id, cipher, &attachment_id)
}

/// The response that tells a client where to send the encrypted content of an attachment.
fn upload_response(
    user_id: &str,
    cipher_id: &str,
    cipher: JsonObject,
    attachment_id: &str,
) -> LocalResponse {
    let upload = json!({
        "attachmentId": attachment_id,
        "url": attachment_url(user_id, cipher_id, attachment_id),
        "fileUploadType": FILE_UPLOAD_TYPE_AZURE,
        "cipherResponse": cipher_without_organization(&cipher),
        "object": "attachment-fileUpload",
    });
    ok_response(&upload)
}

fn attachment_url(user_id: &str, cipher_id: &str, attachment_id: &str) -> String {
    format!("https://{LOCAL_VAULT_HOST}/{ATTACHMENTS_PATH}/{user_id}/{cipher_id}/{attachment_id}")
}

fn folder_json(id: &str, name: Option<&Value>, now: &str) -> JsonObject {
    let name = name.cloned().unwrap_or(Value::Null);
    let folder = json!({"id": id, "name": name, "revisionDate": now, "object": "folder"});
    into_object(folder)
}

/// Converts the item of a request to the form that the server returns it in, and that it is
/// stored in. What a request does not carry is taken from the item that it replaces.
fn to_cipher(body: &JsonObject, id: &str, existing: Option<&JsonObject>, now: &str) -> JsonObject {
    let creation_date = existing
        .and_then(|cipher| cipher.get("creationDate"))
        .cloned()
        .unwrap_or_else(|| Value::from(now));
    let deleted_date = existing
        .and_then(|cipher| cipher.get("deletedDate"))
        .cloned()
        .unwrap_or(Value::Null);
    with_fields(
        &without_fields(body, &REQUEST_FIELDS),
        [
            ("id", Value::from(id)),
            ("organizationId", Value::Null),
            ("collectionIds", json!([])),
            ("edit", Value::Bool(true)),
            ("viewPassword", Value::Bool(true)),
            ("organizationUseTotp", Value::Bool(false)),
            ("permissions", json!({"delete": true, "restore": true})),
            ("attachments", attachments_of(body, existing)),
            ("creationDate", creation_date),
            ("deletedDate", deleted_date),
            ("revisionDate", Value::from(now)),
            ("object", Value::from("cipherDetails")),
        ],
    )
}

/// Returns the attachments of the item that a request replaces, with the names and keys that
/// the request re-encrypted.
fn attachments_of(body: &JsonObject, existing: Option<&JsonObject>) -> Value {
    let updates = obj(body, "attachments2");
    let attachments = existing.map(|cipher| objects(cipher, "attachments"));
    let mut changed = Vec::new();
    for mut attachment in attachments.unwrap_or_default() {
        let update =
            string(&attachment, "id").and_then(|id| updates.and_then(|updates| obj(updates, id)));
        for key in ["fileName", "key"] {
            let value = update.and_then(|update| element(update, key));
            if let Some(value) = value.filter(|value| !value.is_null()) {
                attachment.insert(key.to_owned(), value.clone());
            }
        }
        changed.push(attachment);
    }
    array_or_null(changed)
}

/// Returns the response that refuses the item of a request, or `None` if the item can be
/// stored. It has to be encrypted for the account that made the request, and with the user key
/// of that account: a client counts on the server to refuse an item that is not, which could not
/// be decrypted in this vault, and as an update would replace an item that can.
fn refusal(body: &JsonObject, user_id: &str, vault: &JsonObject) -> Option<LocalResponse> {
    let encrypted_for = string(body, "encryptedFor");
    if encrypted_for.is_some_and(|id| !eq_ignore_case(id, user_id)) {
        return Some(bad_request(ENCRYPTED_FOR_ANOTHER_MESSAGE));
    }
    // A request says which key an item was encrypted with by the ID of that key, and the vault
    // has the ID of the user key once a client had it recorded. Without either of them, there is
    // nothing to tell by, and the item is taken as it is.
    let key_id = string(body, "encryptedByKeyId");
    if let (Some(key_id), Some(user_key_id)) = (key_id, recorded_user_key_id(vault))
        && !eq_ignore_case(key_id, user_key_id)
    {
        return Some(bad_request(ENCRYPTED_BY_ANOTHER_KEY_MESSAGE));
    }
    None
}

fn is_out_of_date(cipher: &JsonObject, last_known_revision_date: Option<&str>) -> bool {
    let last_known = last_known_revision_date.and_then(parse_date_nanos);
    let revision = string(cipher, "revisionDate").and_then(parse_date_nanos);
    match (last_known, revision) {
        (Some(last_known), Some(revision)) => {
            (revision - last_known).abs() > OUT_OF_DATE_TOLERANCE_NANOS
        }
        _ => false,
    }
}

/// The response with an item, as an item of the user: whatever a file of the vault says about an
/// organization of the item is left out of what a client is told (see `organizations`).
fn cipher_response(cipher: &JsonObject) -> LocalResponse {
    ok_response(&Value::Object(cipher_without_organization(cipher)))
}

/// The response with a list of items, as items of the user (see [`cipher_response`]).
fn list_of(ciphers: Vec<JsonObject>) -> LocalResponse {
    let ciphers = ciphers
        .iter()
        .map(|cipher| Value::Object(cipher_without_organization(cipher)))
        .collect();
    list_response(ciphers)
}

/// The response with the first of the items, as an item of the user (see [`cipher_response`]).
fn first_or_not_found(ciphers: Vec<JsonObject>) -> LocalResponse {
    match ciphers.first() {
        Some(cipher) => cipher_response(cipher),
        None => not_found_response(),
    }
}

fn cipher_and_attachment(
    vault: &JsonObject,
    cipher_id: &str,
    attachment_id: &str,
) -> Option<(JsonObject, JsonObject)> {
    let cipher = item(vault, CIPHERS, cipher_id)?;
    let attachments = objects(&cipher, "attachments");
    let attachment = attachments
        .into_iter()
        .find(|attachment| has_id(attachment, attachment_id))?;
    Some((cipher, attachment))
}

/// Returns `true` if the item, folder or attachment has the ID, in whatever case.
fn has_id(object: &JsonObject, id: &str) -> bool {
    let own_id = string(object, "id");
    own_id.is_some_and(|own_id| eq_ignore_case(own_id, id))
}

/// Returns the ID that the vault has the item, folder or attachment under. It was found by the
/// ID of a request, which may differ from it in case. What is stored, and the names of the files
/// of attachments, follow the vault and not the request: a file is not found under a name in
/// another case wherever the two are told apart.
fn id_of(object: &JsonObject, requested_id: &str) -> String {
    string(object, "id").unwrap_or(requested_id).to_owned()
}

fn array_or_null(list: Vec<JsonObject>) -> Value {
    if list.is_empty() {
        Value::Null
    } else {
        Value::Array(list.into_iter().map(Value::Object).collect())
    }
}

fn items(vault: &JsonObject, key: &str) -> Vec<JsonObject> {
    obj(vault, KEY_SYNC)
        .map(|sync| objects(sync, key))
        .unwrap_or_default()
}

fn item(vault: &JsonObject, key: &str, id: &str) -> Option<JsonObject> {
    items(vault, key).into_iter().find(|item| has_id(item, id))
}

fn items_with_ids(vault: &JsonObject, key: &str, ids: &[String]) -> Vec<JsonObject> {
    let has_any_id = |item: &JsonObject| ids.iter().any(|id| has_id(item, id));
    items(vault, key).into_iter().filter(has_any_id).collect()
}

/// Returns the IDs of the items that have one of the IDs, the way the vault has them.
fn existing_ids(vault: &JsonObject, key: &str, ids: &[String]) -> Vec<String> {
    items_with_ids(vault, key, ids)
        .iter()
        .filter_map(|item| string(item, "id").map(str::to_owned))
        .collect()
}

fn with_items(vault: &JsonObject, key: &str, list: Vec<JsonObject>) -> JsonObject {
    let sync = obj(vault, KEY_SYNC).cloned().unwrap_or_default();
    let list = Value::Array(list.into_iter().map(Value::Object).collect());
    let sync = with_fields(&sync, [(key, list)]);
    with_fields(vault, [(KEY_SYNC, Value::Object(sync))])
}

/// Returns the vault with the item in place of the one with the same ID, or added if there is
/// none.
fn with_item(vault: &JsonObject, key: &str, new_item: &JsonObject) -> JsonObject {
    let id = string(new_item, "id").unwrap_or_default();
    let mut list = items(vault, key);
    match list.iter_mut().find(|item| has_id(item, id)) {
        Some(existing) => existing.clone_from(new_item),
        None => list.push(new_item.clone()),
    }
    with_items(vault, key, list)
}

/// Returns the vault with each of the items that have one of the IDs changed.
fn with_each_item(
    vault: &JsonObject,
    key: &str,
    ids: &[String],
    change: impl Fn(&JsonObject) -> JsonObject,
) -> JsonObject {
    let mut list = items(vault, key);
    for item in &mut list {
        if ids.iter().any(|id| has_id(item, id)) {
            *item = change(item);
        }
    }
    with_items(vault, key, list)
}

fn without_items(vault: &JsonObject, key: &str, ids: &[String]) -> JsonObject {
    let has_none_of_the_ids = |item: &JsonObject| !ids.iter().any(|id| has_id(item, id));
    let list = items(vault, key).into_iter().filter(has_none_of_the_ids);
    with_items(vault, key, list.collect())
}

/// Returns the vault without the folders. The items that were in them are in no folder from then
/// on, as the vault is put together with the items of a deleted folder in none (see
/// `merge::without_deleted_folders`). They are not changed for it: as new versions of the items,
/// the deletion would win over a change of one of them that another device made before the
/// deletion came to it, and the change would be lost.
fn without_folders(vault: &JsonObject, folder_ids: &[String]) -> JsonObject {
    without_items(vault, FOLDERS, folder_ids)
}

/// Returns the size of a file the way the server describes it, such as `2.00 KB`. The fraction is
/// rounded half up.
fn size_name(size: u64) -> String {
    let rounded_hundredths = |unit: u64| {
        let size = u128::from(size) * 100;
        let unit = u128::from(unit);
        (size + unit / 2) / unit
    };
    if size >= BYTES_PER_MB {
        let hundredths = rounded_hundredths(BYTES_PER_MB);
        format!("{}.{:02} MB", hundredths / 100, hundredths % 100)
    } else if size >= BYTES_PER_KB {
        let hundredths = rounded_hundredths(BYTES_PER_KB);
        format!("{}.{:02} KB", hundredths / 100, hundredths % 100)
    } else {
        format!("{size} Bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_are_described_with_two_decimals_rounded_half_up() {
        assert_eq!(size_name(0), "0 Bytes");
        assert_eq!(size_name(1023), "1023 Bytes");
        assert_eq!(size_name(1024), "1.00 KB");
        assert_eq!(size_name(2048), "2.00 KB");
        // 1.125 KB, which is exactly between two hundredths.
        assert_eq!(size_name(1152), "1.13 KB");
        assert_eq!(size_name(1_048_575), "1024.00 KB");
        assert_eq!(size_name(1_048_576), "1.00 MB");
        assert_eq!(size_name(1_572_864), "1.50 MB");
    }
}
