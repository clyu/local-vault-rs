//! The tokens that the local server hands out.
//!
//! The access token has the shape of the JWT that the Bitwarden identity server issues, since
//! the clients read the account it belongs to from its claims. It is not signed: it never leaves
//! the client, and everything it gives access to is encrypted with keys that it does not hold.
//!
//! Both tokens say which user key the account had when they were issued, as a client that was
//! given them has that key, and encrypts with it. Once the key is rotated, they are refused (see
//! `rotation`).

use serde_json::{Value, json};

use crate::json::{base64_url_decode, base64_url_encode, is_safe_segment, string};
use crate::merge::KeyRotation;

const REFRESH_TOKEN_PREFIX: &str = "local-refresh.";

/// The claim of an access token with the rotation that made the user key of the account when the
/// token was issued. A token without it was issued while the account had the key that it was
/// registered with.
const USER_KEY_CLAIM: &str = "user_key";

/// What an access token says about the account that it is for.
pub(crate) struct AccessTokenClaims<'a> {
    pub(crate) user_id: &'a str,
    pub(crate) email: &'a str,
    pub(crate) name: Option<&'a str>,
    /// The client that asked for the token, which it reads back to ask for the next one.
    pub(crate) client_id: Option<&'a str>,
    pub(crate) expires_at_epoch_seconds: i64,
    /// The rotation that made the user key of the account, or `None` for the key that the
    /// account was registered with.
    pub(crate) user_key: Option<&'a KeyRotation>,
}

/// Whom a token was issued to: the account, and the user key that it had then.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Bearer {
    pub(crate) user_id: String,
    /// The rotation that made the user key of the account when the token was issued, or `None`
    /// for the key that the account was registered with.
    pub(crate) user_key: Option<KeyRotation>,
}

/// Creates an access token for an account.
pub(crate) fn create_access_token(claims: &AccessTokenClaims<'_>) -> String {
    let header = json!({"alg": "none", "typ": "JWT"});
    let mut payload = json!({
        "sub": claims.user_id,
        "email": claims.email,
        "email_verified": true,
        "name": claims.name,
        "premium": true,
        "exp": claims.expires_at_epoch_seconds.min(i64::from(i32::MAX)),
        "amr": ["Application"],
        "client_id": claims.client_id,
    });
    if let (Some(user_key), Value::Object(payload)) = (claims.user_key, &mut payload) {
        payload.insert(USER_KEY_CLAIM.to_owned(), user_key.to_json());
    }
    [header.to_string(), payload.to_string(), "local".to_owned()]
        .iter()
        .map(|part| base64_url_encode(part.as_bytes()))
        .collect::<Vec<_>>()
        .join(".")
}

/// Returns whom an access token was issued to, or `None` if it is not an access token.
pub(crate) fn bearer_of_access_token(access_token: &str) -> Option<Bearer> {
    let parts: Vec<&str> = access_token.split('.').collect();
    let [_, payload, _] = parts.as_slice() else {
        return None;
    };
    let claims: Value = serde_json::from_str(&base64_url_decode(payload)?).ok()?;
    let claims = claims.as_object()?;
    let user_key = match claims.get(USER_KEY_CLAIM) {
        None | Some(Value::Null) => None,
        Some(user_key) => Some(KeyRotation::read(user_key)?),
    };
    Some(Bearer {
        user_id: string(claims, "sub")?.to_owned(),
        user_key,
    })
}

/// Creates a refresh token for an account that has the user key that the rotation made, or the
/// one that it was registered with: `local-refresh.<account id>`, followed by `.<at>.<by>` of the
/// rotation if there is one.
pub(crate) fn create_refresh_token(user_id: &str, user_key: Option<&KeyRotation>) -> String {
    match user_key {
        None => format!("{REFRESH_TOKEN_PREFIX}{user_id}"),
        Some(key) => format!("{REFRESH_TOKEN_PREFIX}{user_id}.{}.{}", key.at, key.by),
    }
}

/// Returns whom a refresh token was issued to, or `None` if it is not a refresh token.
pub(crate) fn bearer_of_refresh_token(refresh_token: &str) -> Option<Bearer> {
    let parts: Vec<&str> = refresh_token
        .strip_prefix(REFRESH_TOKEN_PREFIX)?
        .splitn(3, '.')
        .collect();
    let (user_id, user_key) = match parts.as_slice() {
        [user_id] => (*user_id, None),
        [user_id, at, by] => {
            let at = at.parse().ok()?;
            (
                *user_id,
                Some(KeyRotation {
                    at,
                    by: (*by).to_owned(),
                }),
            )
        }
        _ => return None,
    };
    is_safe_segment(user_id).then(|| Bearer {
        user_id: user_id.to_owned(),
        user_key,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn claims<'a>(user_key: Option<&'a KeyRotation>) -> AccessTokenClaims<'a> {
        AccessTokenClaims {
            user_id: "user-id",
            email: "user@example.com",
            name: None,
            client_id: Some("browser"),
            expires_at_epoch_seconds: i64::MAX,
            user_key,
        }
    }

    fn bearer(user_key: Option<KeyRotation>) -> Bearer {
        Bearer {
            user_id: "user-id".to_owned(),
            user_key,
        }
    }

    #[test]
    fn an_access_token_carries_the_id_of_its_account_and_its_user_key() {
        let rotation = KeyRotation {
            at: 1_000,
            by: "device-a".to_owned(),
        };

        let token = create_access_token(&claims(None));
        let rotated = create_access_token(&claims(Some(&rotation)));

        assert_eq!(token.split('.').count(), 3);
        assert_eq!(bearer_of_access_token(&token), Some(bearer(None)));
        assert_eq!(
            bearer_of_access_token(&rotated),
            Some(bearer(Some(rotation)))
        );
        assert_eq!(bearer_of_access_token("not-a-token"), None);
        assert_eq!(bearer_of_access_token("a.b.c"), None);
    }

    #[test]
    fn an_access_token_with_a_user_key_that_is_not_a_rotation_is_not_one() {
        let payload = json!({"sub": "user-id", USER_KEY_CLAIM: "key"}).to_string();
        let payload = base64_url_encode(payload.as_bytes());

        assert_eq!(bearer_of_access_token(&format!("e30.{payload}.x")), None);
    }

    #[test]
    fn a_refresh_token_carries_the_id_of_its_account_and_its_user_key() {
        let rotation = KeyRotation {
            at: 1_000,
            by: "device-a".to_owned(),
        };

        let token = create_refresh_token("user-id", None);
        let rotated = create_refresh_token("user-id", Some(&rotation));

        assert_eq!(bearer_of_refresh_token(&token), Some(bearer(None)));
        assert_eq!(rotated, "local-refresh.user-id.1000.device-a");
        assert_eq!(
            bearer_of_refresh_token(&rotated),
            Some(bearer(Some(rotation)))
        );
        assert_eq!(bearer_of_refresh_token("local-refresh.../x"), None);
        assert_eq!(
            bearer_of_refresh_token("local-refresh.user-id.later.a"),
            None
        );
        assert_eq!(bearer_of_refresh_token("local-refresh.user-id.1000"), None);
        assert_eq!(bearer_of_refresh_token("other"), None);
    }
}
