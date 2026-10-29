//! What the local server leaves out of what it returns: organizations.
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
//! A client may read a field by a key in another case than the server writes it in: the browser
//! extension takes `Organizations` before `organizations`. A field is therefore replaced in
//! whatever case it is written in (see [`with_fields_replaced`]).

use serde_json::{Value, json};

use crate::json::{JsonObject, eq_ignore_case, with_fields_replaced};

/// Returns the `sync` of a vault as `GET sync` returns it: without the collections and the
/// policies of organizations, and with the profile and the items without organizations.
pub(crate) fn sync_without_organizations(sync: &JsonObject) -> JsonObject {
    let mut sync = with_fields_replaced(
        sync,
        [
            ("collections", json!([])),
            ("policies", json!([])),
            ("policiesNew", json!([])),
        ],
    );
    // In whatever case they are written in, as a client may read either.
    for (key, value) in sync.iter_mut() {
        if eq_ignore_case(key, "profile")
            && let Value::Object(profile) = value
        {
            *profile = profile_without_organizations(profile);
        } else if eq_ignore_case(key, "ciphers")
            && let Value::Array(ciphers) = value
        {
            for cipher in ciphers {
                if let Value::Object(fields) = cipher {
                    *fields = cipher_without_organization(fields);
                }
            }
        }
    }
    sync
}

/// Returns the profile of an account without the organizations and the providers that it is in,
/// and without what an organization does to the account: that it has its key in a Key
/// Connector, and that an administrator reset its master password, which the user would have to
/// replace.
pub(crate) fn profile_without_organizations(profile: &JsonObject) -> JsonObject {
    with_fields_replaced(
        profile,
        [
            ("organizations", json!([])),
            ("organizationsNew", json!([])),
            ("providers", json!([])),
            ("providerOrganizations", json!([])),
            ("usesKeyConnector", Value::Bool(false)),
            ("forcePasswordReset", Value::Bool(false)),
        ],
    )
}

/// Returns an item as an item of the user, in no organization and in none of its collections.
pub(crate) fn cipher_without_organization(cipher: &JsonObject) -> JsonObject {
    with_fields_replaced(
        cipher,
        [
            ("organizationId", Value::Null),
            ("collectionIds", json!([])),
        ],
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn object(value: Value) -> JsonObject {
        value.as_object().cloned().unwrap()
    }

    #[test]
    fn a_vault_is_returned_without_organizations_in_whatever_case_they_are_written() {
        let organization = json!({"id": "organization", "key": "4.organizationKey"});
        let cipher =
            json!({"id": "item", "OrganizationId": "organization", "collectionIds": ["c"]});
        let sync = object(json!({
            "profile": {"id": "user", "organizations": [organization], "usesKeyConnector": true},
            "Profile": {"Organizations": [organization], "ForcePasswordReset": true},
            "ciphers": [cipher, {"id": "mine", "organizationId": null}],
            "Collections": [{"id": "c", "organizationId": "organization"}],
            "policies": [{"organizationId": "organization", "type": 0, "enabled": true}],
            "folders": [{"id": "folder", "organizationId": "kept"}],
        }));

        let returned = sync_without_organizations(&sync);

        let expected = json!({
            "profile": {"id": "user", "organizations": [], "usesKeyConnector": false},
            "Profile": {"organizations": [], "forcePasswordReset": false},
            "ciphers": [
                {"id": "item", "collectionIds": [], "organizationId": null},
                {"id": "mine", "organizationId": null},
            ],
            "policies": [],
            "folders": [{"id": "folder", "organizationId": "kept"}],
            "collections": [],
        });
        assert_eq!(Value::Object(returned), expected);
    }

    #[test]
    fn a_vault_without_organizations_is_returned_as_it_is() {
        let sync = object(json!({
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
            "ciphers": [{"id": "item", "organizationId": null, "collectionIds": []}],
            "policies": [],
            "unknown": {"organizations": ["kept"]},
        }));

        let returned = sync_without_organizations(&sync);

        assert_eq!(
            Value::Object(returned).to_string(),
            Value::Object(sync).to_string()
        );
    }
}
