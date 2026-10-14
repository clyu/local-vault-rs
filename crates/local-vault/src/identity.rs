//! What the Bitwarden identity server does: it registers accounts and signs them in.

use serde_json::{Value, json};

use crate::account::{
    master_password_unlock, password_verifier, profile, to_master_password_unlock,
};
use crate::fs::FileSystem;
use crate::http::{
    HTTP_BAD_REQUEST, LocalRequest, LocalResponse, bad_request, json_response, ok_response,
};
use crate::json::{
    JsonObject, base64_url_decode, base64_url_encode, int, int_or_null, into_object, is_blank,
    normalize_email, obj, string,
};
use crate::platform::Platform;
use crate::server::{LocalServer, Outcome};
use crate::store::{LOCAL_VAULT_FORMAT, LOCAL_VAULT_VERSION};
use crate::token::{
    AccessTokenClaims, create_access_token, create_refresh_token, user_id_of_refresh_token,
};
use crate::verifier::{create_verifier, matches_verifier};

const TOKEN_LIFETIME_SECONDS: i64 = 5 * 365 * 24 * 60 * 60;
const DEFAULT_KDF_ITERATIONS: i64 = 600_000;
const KDF_TYPE_PBKDF2: i64 = 0;

const EMAIL_REQUIRED_MESSAGE: &str = "An email is required.";
const INCOMPLETE_REGISTRATION_MESSAGE: &str = "The registration is not complete.";
const WRONG_PASSWORD_MESSAGE: &str = "Username or password is incorrect. Try again.";
const PASSWORD_ONLY_MESSAGE: &str =
    "Only a master password can be used to sign in to a local vault.";

/// What a registration has to come with.
struct Registration<'a> {
    email: String,
    public_key: &'a str,
    private_key: &'a str,
    password_hash: &'a str,
    unlock: JsonObject,
}

impl<'a> Registration<'a> {
    /// Reads the registration from the body of its request, or returns `None` if any of it is
    /// missing.
    fn read(body: &'a JsonObject) -> Option<Self> {
        let email = normalize_email(string(body, "email")?);
        let keys = obj(body, "userAsymmetricKeys")?;
        let authentication = obj(body, "MasterPasswordAuthentication")?;
        Some(Self {
            email: Some(email).filter(|email| !email.is_empty())?,
            public_key: string(keys, "publicKey")?,
            private_key: string(keys, "encryptedPrivateKey")?,
            password_hash: string(authentication, "MasterPasswordAuthenticationHash")?,
            unlock: to_master_password_unlock(obj(body, "MasterPasswordUnlock")?)?,
        })
    }
}

impl<F: FileSystem, P: Platform> LocalServer<F, P> {
    /// There is nobody to send an email, so the token that the email would have carried is
    /// returned right away, the way a server without email verification does.
    pub(crate) async fn send_verification_email(&self, request: &LocalRequest) -> Outcome {
        let body = request.json_body()?;
        let email = normalize_email(string(&body, "email").unwrap_or_default());
        if email.is_empty() {
            return Ok(bad_request(EMAIL_REQUIRED_MESSAGE));
        }
        if self.store.find_account_id(&email).await?.is_some() {
            return Ok(email_taken(&email));
        }
        let token = json!({"email": email, "name": string(&body, "name")});
        let token = base64_url_encode(token.to_string().as_bytes());
        Ok(ok_response(&Value::String(token)))
    }

    /// Creates the vault of a new account from the keys that the client generated for it.
    pub(crate) async fn register_finish(&self, request: &LocalRequest) -> Outcome {
        let body = request.json_body()?;
        let Some(registration) = Registration::read(&body) else {
            return Ok(bad_request(INCOMPLETE_REGISTRATION_MESSAGE));
        };
        let email = registration.email.as_str();
        if self.store.find_account_id(email).await?.is_some() {
            return Ok(email_taken(email));
        }
        let user_id = self.new_id();
        let now = self.now();
        let token = string(&body, "emailVerificationToken");
        let name = token.and_then(|token| registered_name(token, email));
        let unlock = &registration.unlock;
        let user_key = unlock.get("masterKeyEncryptedUserKey").cloned();
        let private_key = registration.private_key;
        let account_keys = json!({
            "publicKeyEncryptionKeyPair": {
                "wrappedPrivateKey": private_key,
                "publicKey": registration.public_key,
                "signedPublicKey": null,
            },
            "signatureKeyPair": null,
            "securityState": null,
        });
        let profile = json!({
            "id": user_id,
            "name": name,
            "email": email,
            "emailVerified": true,
            "premium": true,
            "premiumFromOrganization": false,
            "masterPasswordHint": string(&body, "masterPasswordHint"),
            "culture": "en-US",
            "twoFactorEnabled": false,
            "key": user_key,
            "privateKey": private_key,
            "accountKeys": account_keys,
            "securityStamp": self.new_id(),
            "forcePasswordReset": false,
            "usesKeyConnector": false,
            "avatarColor": null,
            "creationDate": now,
            "organizations": [],
            "providers": [],
            "providerOrganizations": [],
            "object": "profile",
        });
        let domains = json!({
            "equivalentDomains": [],
            "globalEquivalentDomains": [],
            "object": "domains",
        });
        let sync = json!({
            "profile": profile,
            "folders": [],
            "collections": [],
            "ciphers": [],
            "policies": [],
            "sends": [],
            "domains": domains,
            "userDecryption": {"masterPasswordUnlock": unlock},
            "object": "sync",
        });
        let verifier = create_verifier(&self.platform, registration.password_hash);
        let vault = json!({
            "format": LOCAL_VAULT_FORMAT,
            "version": LOCAL_VAULT_VERSION,
            "revisionDate": now,
            "account": {"masterPasswordVerifier": verifier},
            "sync": sync,
        });
        self.store
            .write_vault(&user_id, &into_object(vault))
            .await?;
        Ok(ok_response(&json!({"object": "register"})))
    }

    /// Returns how the master key of the account with the email is derived. An email that no
    /// account has gets the defaults, so that this does not tell which emails have an account.
    ///
    /// There is no master password yet to tell several accounts with the email apart by, so the
    /// answer is about the first of them. Another one can only be signed in to if its master key
    /// is derived the same way.
    pub(crate) async fn pre_login(&self, request: &LocalRequest) -> Outcome {
        let body = request.json_body()?;
        let email = string(&body, "email");
        let vault = match email {
            Some(email) => self.first_vault_of(email).await?,
            None => None,
        };
        let unlock = vault.as_ref().and_then(master_password_unlock);
        let kdf = unlock.and_then(|unlock| obj(unlock, "kdf"));
        let kdf_int = |key: &str| kdf.and_then(|kdf| int(kdf, key));
        let kdf_type = kdf_int("kdfType").unwrap_or(KDF_TYPE_PBKDF2);
        let iterations = kdf_int("iterations").unwrap_or(DEFAULT_KDF_ITERATIONS);
        let memory = int_or_null(kdf, "memory");
        let parallelism = int_or_null(kdf, "parallelism");
        let salt = match unlock.and_then(|unlock| string(unlock, "salt")) {
            Some(salt) => salt.to_owned(),
            None => normalize_email(email.unwrap_or_default()),
        };
        let kdf_settings = json!({
            "kdfType": kdf_type,
            "iterations": iterations,
            "memory": memory,
            "parallelism": parallelism,
        });
        let pre_login = json!({
            "kdf": kdf_type,
            "kdfIterations": iterations,
            "kdfMemory": memory,
            "kdfParallelism": parallelism,
            "kdfSettings": kdf_settings,
            "salt": salt,
        });
        Ok(ok_response(&pre_login))
    }

    /// Signs an account in with the hash of its master password, or renews the tokens of an
    /// account that is signed in.
    pub(crate) async fn token(&self, request: &LocalRequest) -> Outcome {
        match request.form_field("grant_type") {
            Some("password") => self.password_grant(request).await,
            Some("refresh_token") => self.refresh_token_grant(request).await,
            _ => Ok(invalid_grant(PASSWORD_ONLY_MESSAGE)),
        }
    }

    async fn password_grant(&self, request: &LocalRequest) -> Outcome {
        let email = request.form_field("username").unwrap_or_default();
        let password_hash = request.form_field("password").unwrap_or_default();
        // A vault folder can hold more than one account with an email, which only their master
        // passwords tell apart.
        let mut account = None;
        for account_id in self.store.find_account_ids(email).await? {
            let vault = self.store.read_vault(&account_id).await?;
            if let Some(vault) = vault
                && matches_verifier(password_verifier(&vault), password_hash)
            {
                account = Some((account_id, vault));
                break;
            }
        }
        let Some((user_id, vault)) = account else {
            return Ok(invalid_grant(WRONG_PASSWORD_MESSAGE));
        };
        let profile = profile(&vault);
        let unlock = master_password_unlock(&vault);
        let kdf = unlock.and_then(|unlock| obj(unlock, "kdf"));
        let kdf_type = kdf.and_then(|kdf| int(kdf, "kdfType"));
        let field = |key: &str| profile.get(key).cloned().unwrap_or(Value::Null);
        let login = json!({
            "scope": "api offline_access",
            "Key": field("key"),
            "PrivateKey": field("privateKey"),
            "AccountKeys": field("accountKeys"),
            "Kdf": kdf_type.unwrap_or(KDF_TYPE_PBKDF2),
            "KdfIterations": int_or_null(kdf, "iterations"),
            "KdfMemory": int_or_null(kdf, "memory"),
            "KdfParallelism": int_or_null(kdf, "parallelism"),
            "ForcePasswordReset": false,
            "ResetMasterPassword": false,
            "UserDecryptionOptions": {
                "hasMasterPassword": true,
                "masterPasswordUnlock": unlock,
                "object": "userDecryptionOptions",
            },
        });
        let mut body = self.tokens(&user_id, &profile, request);
        body.extend(into_object(login));
        Ok(ok_response(&Value::Object(body)))
    }

    async fn refresh_token_grant(&self, request: &LocalRequest) -> Outcome {
        let refresh_token = request.form_field("refresh_token").unwrap_or_default();
        let Some(user_id) = user_id_of_refresh_token(refresh_token) else {
            return Ok(unknown_refresh_token());
        };
        let Some(vault) = self.store.read_vault(user_id).await? else {
            return Ok(unknown_refresh_token());
        };
        let tokens = self.tokens(user_id, &profile(&vault), request);
        Ok(ok_response(&Value::Object(tokens)))
    }

    fn tokens(&self, user_id: &str, profile: &JsonObject, request: &LocalRequest) -> JsonObject {
        let now_seconds = self.platform.now_millis().div_euclid(1000);
        let claims = AccessTokenClaims {
            user_id,
            email: string(profile, "email").unwrap_or_default(),
            name: string(profile, "name"),
            // The client reads this back to ask for the next token.
            client_id: request.form_field("client_id"),
            expires_at_epoch_seconds: now_seconds + TOKEN_LIFETIME_SECONDS,
        };
        let tokens = json!({
            "access_token": create_access_token(&claims),
            "expires_in": TOKEN_LIFETIME_SECONDS,
            "refresh_token": create_refresh_token(user_id),
            "token_type": "Bearer",
        });
        into_object(tokens)
    }
}

fn email_taken(email: &str) -> LocalResponse {
    bad_request(&format!("Email '{email}' is already taken."))
}

fn invalid_grant(message: &str) -> LocalResponse {
    let error = json!({
        "error": "invalid_grant",
        "error_description": "invalid_username_or_password",
        "ErrorModel": {"Message": message, "Object": "error"},
    });
    json_response(&error, HTTP_BAD_REQUEST)
}

fn unknown_refresh_token() -> LocalResponse {
    json_response(&json!({"error": "invalid_grant"}), HTTP_BAD_REQUEST)
}

/// Reads the name that was given when the registration was started from the token that
/// [`LocalServer::send_verification_email`] returned for the email.
fn registered_name(token: &str, email: &str) -> Option<String> {
    let claims: Value = serde_json::from_str(&base64_url_decode(token)?).ok()?;
    let claims = claims.as_object()?;
    if string(claims, "email") != Some(email) {
        return None;
    }
    let name = string(claims, "name").filter(|name| !is_blank(name));
    name.map(str::to_owned)
}
