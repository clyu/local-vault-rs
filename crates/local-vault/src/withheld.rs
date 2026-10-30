//! What the local server leaves out of what it returns: organizations, and the domains that a
//! client takes for the same site.
//!
//! An account of a local vault is never in an organization and has no provider, as both need a
//! Bitwarden server. Whoever can write to the vault folder can still put them in a file of the
//! vault, as a device writes whatever it likes in its own file: an organization of their own, with
//! its key encrypted with the public key of the account, which the vault folder holds. A client
//! that is told that the account is in it takes that key in. It then decrypts the items of the
//! organization, which are theirs, offers to put new items in it, which they can decrypt, applies
//! its policies, and sends the key of the account to its Key Connector once the user agrees to
//! leave the master password behind. A Bitwarden server that does that is what the security
//! principles of Bitwarden guard a client against (P01), and here, whatever can write to the
//! vault folder is in the place of the server.
//!
//! So what a file says about organizations is left out of every response that a client could
//! learn of them from: the vault that `GET sync` returns, the profile and every item. They are
//! returned the way the vault of an account has them that has never been in an organization, as
//! a registration writes it. An item of an organization is returned as an item of the user, which
//! the client cannot decrypt rather than take in. The files are left as they are: only what a
//! client is told changes.
//!
//! The same goes for the domains that a client takes for the same site, which a Bitwarden server
//! keeps for an account unencrypted: a client offers the logins of one of them, and fills them
//! in, on the others. Whoever can write to the vault folder could have a site of their own taken
//! for the bank of the user, which would then be offered the login for the bank. A local vault
//! has none, as only a Bitwarden server lets them be set, so they are returned the way a
//! registration writes them.
//!
//! It is all left out in one place, on the way of a response to the client ([`withhold`]),
//! rather than by each route that reads the vault. Every route of an account says what of the
//! vault its response has ([`Returned`]), in a match that names every route, so that no route can
//! be added without saying it.
//!
//! The vault, its profile and how it is unlocked are written by the local server alone, so only
//! the fields that it writes of them are returned, under the keys that it writes them under
//! ([`SYNC_FIELDS`], [`PROFILE_FIELDS`], [`USER_DECRYPTION_FIELDS`]). A field that a client comes
//! to read, as an update of a client or of the SDK may, such as one more about organizations, is
//! then not returned before the server writes it, rather than whatever a file says in it. A key
//! in another case is left out as well, as a client may read a field by it: the browser extension
//! takes `Organizations` before `organizations`.
//!
//! The items are written by the clients, with fields that the server does not know of, so they
//! are returned with all of them, and only their organization is replaced, in whatever case its
//! key is written in (see [`replace_fields`]).

use serde_json::{Value, json};

use crate::http::{LocalResponse, ResponseBody};
use crate::json::{JsonObject, replace_fields};

/// The fields of the `sync` of a vault that the local server writes, as a registration writes
/// them, which are all that is returned of it. A field that the server comes to write has to be
/// added here, or no client is told it.
const SYNC_FIELDS: [&str; 9] = [
    "profile",
    "folders",
    "collections",
    "ciphers",
    "policies",
    "sends",
    "domains",
    "userDecryption",
    "object",
];

/// The fields of the profile of an account that the local server writes (see [`SYNC_FIELDS`]).
const PROFILE_FIELDS: [&str; 21] = [
    "id",
    "name",
    "email",
    "emailVerified",
    "premium",
    "premiumFromOrganization",
    "masterPasswordHint",
    "culture",
    "twoFactorEnabled",
    "key",
    "privateKey",
    "accountKeys",
    "securityStamp",
    "forcePasswordReset",
    "usesKeyConnector",
    "avatarColor",
    "creationDate",
    "organizations",
    "providers",
    "providerOrganizations",
    "object",
];

/// The fields of how the vault is unlocked that the local server writes (see [`SYNC_FIELDS`]).
const USER_DECRYPTION_FIELDS: [&str; 2] = ["masterPasswordUnlock", "userKeyId"];

/// What of the vault the response to a request has, which tells what is left out of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Returned {
    /// Nothing that a file of the vault could say about organizations or domains in: nothing of
    /// the vault, or only folders, attachments or devices, which a client reads none of it from.
    Nothing,
    /// The vault, as `GET sync` returns it.
    Vault,
    /// The profile of the account.
    Profile,
    /// An item.
    Cipher,
    /// A list of items.
    Ciphers,
    /// An item under the key, along with what else the response says.
    CipherUnder(&'static str),
}

/// Returns the response without what the vault in it says about organizations and equivalent
/// domains. The vault is returned the way a registration writes it, the profile and the items
/// without organizations.
pub(crate) fn withhold(returned: Returned, response: LocalResponse) -> LocalResponse {
    let ResponseBody::Json(json) = &response.body else {
        return response;
    };
    if returned == Returned::Nothing {
        return response;
    }
    // The body is what the server wrote of a value, so it is read back. One that could not be
    // would be returned as nothing rather than as it is.
    let mut body = serde_json::from_str(json).unwrap_or(Value::Null);
    match returned {
        Returned::Nothing => {}
        Returned::Vault => {
            if let Value::Object(sync) = &mut body {
                withhold_from_sync(sync);
            }
        }
        Returned::Profile => {
            if let Value::Object(profile) = &mut body {
                withhold_from_profile(profile);
            }
        }
        Returned::Cipher => withhold_from_cipher(&mut body),
        Returned::Ciphers => {
            if let Some(ciphers) = body.get_mut("data") {
                withhold_from_ciphers(ciphers);
            }
        }
        Returned::CipherUnder(key) => {
            if let Some(cipher) = body.get_mut(key) {
                withhold_from_cipher(cipher);
            }
        }
    }
    let body = ResponseBody::Json(body.to_string());
    LocalResponse { body, ..response }
}

/// Leaves out of the `sync` of a vault what the local server does not write, the collections and
/// the policies of organizations and equivalent domains, and organizations out of its profile and
/// its items.
fn withhold_from_sync(sync: &mut JsonObject) {
    keep_fields(sync, &SYNC_FIELDS);
    replace_fields(
        sync,
        [
            ("collections", json!([])),
            ("policies", json!([])),
            ("domains", no_equivalent_domains()),
        ],
    );
    if let Some(Value::Object(profile)) = sync.get_mut("profile") {
        withhold_from_profile(profile);
    }
    if let Some(Value::Object(user_decryption)) = sync.get_mut("userDecryption") {
        keep_fields(user_decryption, &USER_DECRYPTION_FIELDS);
    }
    if let Some(ciphers) = sync.get_mut("ciphers") {
        withhold_from_ciphers(ciphers);
    }
}

/// Leaves out of the profile of an account what the local server does not write, the
/// organizations and the providers that it is in, and what an organization does to the account:
/// that it has its key in a Key Connector, and that an administrator reset its master password,
/// which the user would have to replace.
fn withhold_from_profile(profile: &mut JsonObject) {
    keep_fields(profile, &PROFILE_FIELDS);
    replace_fields(
        profile,
        [
            ("organizations", json!([])),
            ("providers", json!([])),
            ("providerOrganizations", json!([])),
            ("usesKeyConnector", Value::Bool(false)),
            ("forcePasswordReset", Value::Bool(false)),
        ],
    );
}

/// Leaves every field out of the object but those with the keys, as they are written.
fn keep_fields(object: &mut JsonObject, keys: &[&str]) {
    object.retain(|key, _| keys.contains(&key.as_str()));
}

/// Makes each item of the list an item of the user (see [`withhold_from_cipher`]).
fn withhold_from_ciphers(ciphers: &mut Value) {
    if let Value::Array(ciphers) = ciphers {
        ciphers.iter_mut().for_each(withhold_from_cipher);
    }
}

/// Makes the item an item of the user, in no organization and in none of its collections.
fn withhold_from_cipher(cipher: &mut Value) {
    if let Value::Object(cipher) = cipher {
        replace_fields(
            cipher,
            [
                ("organizationId", Value::Null),
                ("collectionIds", json!([])),
            ],
        );
    }
}

/// The domains of a vault, as a registration writes them and `GET sync` returns them: none that
/// a client takes for the same site, neither of the account nor of the ones that a Bitwarden
/// server knows of.
pub(crate) fn no_equivalent_domains() -> Value {
    json!({
        "equivalentDomains": [],
        "globalEquivalentDomains": [],
        "object": "domains",
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::http::ok_response;

    /// The body of the response with the value, as it reaches the client.
    fn returned(returned: Returned, value: &Value) -> Value {
        let response = withhold(returned, ok_response(value));
        serde_json::from_str(response.json().unwrap()).unwrap()
    }

    #[test]
    fn a_vault_is_returned_without_organizations() {
        let organization = json!({"id": "organization", "key": "4.organizationKey"});
        let cipher =
            json!({"id": "item", "OrganizationId": "organization", "collectionIds": ["c"]});
        let sync = json!({
            "profile": {
                "id": "user",
                "organizations": [organization],
                "providers": [{"id": "provider", "key": "4.providerKey"}],
                "usesKeyConnector": true,
                "forcePasswordReset": true,
            },
            "ciphers": [cipher, {"id": "mine", "organizationId": null}],
            "collections": [{"id": "c", "organizationId": "organization"}],
            "policies": [{"organizationId": "organization", "type": 0, "enabled": true}],
            "folders": [{"id": "folder", "organizationId": "kept"}],
        });

        let returned = returned(Returned::Vault, &sync);

        let expected = json!({
            "profile": {
                "id": "user",
                "organizations": [],
                "providers": [],
                "usesKeyConnector": false,
                "forcePasswordReset": false,
            },
            "ciphers": [
                {"id": "item", "collectionIds": [], "organizationId": null},
                {"id": "mine", "organizationId": null},
            ],
            "collections": [],
            "policies": [],
            "folders": [{"id": "folder", "organizationId": "kept"}],
        });
        assert_eq!(returned, expected);
    }

    #[test]
    fn only_what_the_local_server_writes_of_a_vault_is_returned_under_its_own_keys() {
        let organization = json!({"id": "organization", "key": "4.organizationKey"});
        let item = json!({"id": "item", "login": {"newField": "kept"}, "newField": "kept"});
        let sync = json!({
            "profile": {
                "id": "user",
                "Organizations": [organization],
                "organizationsNew": [organization],
                "UsesKeyConnector": true,
                "newField": "left out",
            },
            "Profile": {"id": "user", "organizations": [organization]},
            "Collections": [{"id": "c", "organizationId": "organization"}],
            "policiesNew": [{"organizationId": "organization", "type": 0, "enabled": true}],
            "userDecryption": {
                "masterPasswordUnlock": {"salt": "salt"},
                "userKeyId": "key",
                "webAuthnPrfOptions": [{"encryptedUserKey": "4.userKey"}],
            },
            "ciphers": [item],
            "newList": [1],
        });

        let vault = returned(Returned::Vault, &sync);
        let profile = returned(Returned::Profile, &sync["profile"]);

        // The items are the clients', with whatever fields they have.
        let expected = json!({
            "profile": {"id": "user"},
            "userDecryption": {"masterPasswordUnlock": {"salt": "salt"}, "userKeyId": "key"},
            "ciphers": [item],
        });
        assert_eq!(vault, expected);
        assert_eq!(profile, json!({"id": "user"}));
    }

    #[test]
    fn a_vault_is_returned_without_equivalent_domains() {
        let same_site = json!(["bank.example", "attacker.example"]);
        let global = json!({"type": 0, "domains": same_site, "excluded": false});
        let sync = json!({
            "domains": {"equivalentDomains": [same_site], "globalEquivalentDomains": [global]},
            "Domains": {"EquivalentDomains": [same_site], "object": "domains"},
            "folders": [],
        });

        let returned = returned(Returned::Vault, &sync);

        let expected = json!({"domains": no_equivalent_domains(), "folders": []});
        assert_eq!(returned, expected);
    }

    #[test]
    fn a_vault_without_organizations_or_equivalent_domains_is_returned_as_it_is() {
        let sync = json!({
            "profile": {
                "id": "user",
                "premiumFromOrganization": false,
                "forcePasswordReset": false,
                "usesKeyConnector": false,
                "organizations": [],
                "providers": [],
                "providerOrganizations": [],
            },
            "folders": [],
            "collections": [],
            "ciphers": [{"id": "item", "organizationId": null, "collectionIds": [], "n": 1.0}],
            "policies": [],
            "domains": no_equivalent_domains(),
            "userDecryption": {"masterPasswordUnlock": {"salt": "salt"}, "userKeyId": "key"},
        });

        let response = withhold(Returned::Vault, ok_response(&sync));

        assert_eq!(response, ok_response(&sync));
    }

    #[test]
    fn an_item_is_returned_as_one_of_the_user_wherever_a_response_has_it() {
        let cipher =
            json!({"id": "item", "organizationId": "organization", "CollectionIds": ["c"]});
        let mine = json!({"id": "item", "organizationId": null, "collectionIds": []});
        let list = json!({"data": [cipher, cipher], "continuationToken": null, "object": "list"});
        let upload = json!({"attachmentId": "attachment", "cipherResponse": cipher});

        let returned_list = returned(Returned::Ciphers, &list);
        let returned_upload = returned(Returned::CipherUnder("cipherResponse"), &upload);

        assert_eq!(returned(Returned::Cipher, &cipher), mine);
        assert_eq!(returned_list["data"], json!([mine, mine]));
        assert_eq!(returned_upload["cipherResponse"], mine);
        assert_eq!(returned_upload["attachmentId"], "attachment");
        // A response that has none of it is left as it is, whatever it looks like.
        let profile = json!({"organizations": ["kept"], "usesKeyConnector": true});
        assert_eq!(returned(Returned::Nothing, &profile), profile);
    }
}
