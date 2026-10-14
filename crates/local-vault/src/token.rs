//! The tokens that the local server hands out.
//!
//! The access token has the shape of the JWT that the Bitwarden identity server issues, since
//! the clients read the account it belongs to from its claims. It is not signed: it never leaves
//! the client, and everything it gives access to is encrypted with keys that it does not hold.

use serde_json::{Value, json};

use crate::json::{base64_url_decode, base64_url_encode, is_safe_segment, string};

const REFRESH_TOKEN_PREFIX: &str = "local-refresh.";

/// What an access token says about the account that it is for.
pub(crate) struct AccessTokenClaims<'a> {
    pub(crate) user_id: &'a str,
    pub(crate) email: &'a str,
    pub(crate) name: Option<&'a str>,
    /// The client that asked for the token, which it reads back to ask for the next one.
    pub(crate) client_id: Option<&'a str>,
    pub(crate) expires_at_epoch_seconds: i64,
}

/// Creates an access token for an account.
pub(crate) fn create_access_token(claims: &AccessTokenClaims<'_>) -> String {
    let header = json!({"alg": "none", "typ": "JWT"});
    let payload = json!({
        "sub": claims.user_id,
        "email": claims.email,
        "email_verified": true,
        "name": claims.name,
        "premium": true,
        "exp": claims.expires_at_epoch_seconds.min(i64::from(i32::MAX)),
        "amr": ["Application"],
        "client_id": claims.client_id,
    });
    [header.to_string(), payload.to_string(), "local".to_owned()]
        .iter()
        .map(|part| base64_url_encode(part.as_bytes()))
        .collect::<Vec<_>>()
        .join(".")
}

/// Returns the ID of the account that an access token was created for, or `None` if it is not
/// an access token.
pub(crate) fn user_id_of_access_token(access_token: &str) -> Option<String> {
    let parts: Vec<&str> = access_token.split('.').collect();
    let [_, payload, _] = parts.as_slice() else {
        return None;
    };
    let claims: Value = serde_json::from_str(&base64_url_decode(payload)?).ok()?;
    string(claims.as_object()?, "sub").map(str::to_owned)
}

/// Creates a refresh token for an account.
pub(crate) fn create_refresh_token(user_id: &str) -> String {
    format!("{REFRESH_TOKEN_PREFIX}{user_id}")
}

/// Returns the ID of the account that a refresh token was created for, or `None` if it is not a
/// refresh token.
pub(crate) fn user_id_of_refresh_token(refresh_token: &str) -> Option<&str> {
    refresh_token
        .strip_prefix(REFRESH_TOKEN_PREFIX)
        .filter(|user_id| is_safe_segment(user_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_access_token_carries_the_id_of_its_account() {
        let token = create_access_token(&AccessTokenClaims {
            user_id: "user-id",
            email: "user@example.com",
            name: None,
            client_id: Some("browser"),
            expires_at_epoch_seconds: i64::MAX,
        });

        assert_eq!(token.split('.').count(), 3);
        assert_eq!(user_id_of_access_token(&token).as_deref(), Some("user-id"));
        assert_eq!(user_id_of_access_token("not-a-token"), None);
        assert_eq!(user_id_of_access_token("a.b.c"), None);
    }

    #[test]
    fn a_refresh_token_carries_the_id_of_its_account() {
        let token = create_refresh_token("user-id");

        assert_eq!(user_id_of_refresh_token(&token), Some("user-id"));
        assert_eq!(user_id_of_refresh_token("local-refresh.../x"), None);
        assert_eq!(user_id_of_refresh_token("other"), None);
    }
}
