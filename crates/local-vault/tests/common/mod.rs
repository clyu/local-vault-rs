//! What the tests of the local server share: a platform whose clock they set, and a client that
//! makes requests the way the apps do.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures::executor::block_on;
use local_vault::{
    ClientKind, FileSystem, IoError, LocalRequest, LocalResponse, LocalServer, LogLevel,
    MemoryFileSystem, Platform, ResponseBody,
};
use serde_json::{Value, json};

pub const EMAIL: &str = "user@example.com";
pub const PASSWORD_HASH: &str = "cGFzc3dvcmQtaGFzaA==";
pub const USER_KEY: &str = "2.userKey|iv|mac";
pub const UNKNOWN_ID: &str = "00000000-0000-4000-8000-000000000000";
pub const UNSUPPORTED_MESSAGE: &str =
    "This feature needs a Bitwarden server and is not available with a local vault.";

/// The increment of SplitMix64.
const GOLDEN_GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;

/// 2026-10-11T12:00:00.000Z.
pub const NOON: i64 = 1_791_720_000_000;
pub const MINUTE: i64 = 60_000;

/// A [`Platform`] with a clock that the test sets, random bytes that are the same in every run,
/// and a log that the test reads.
#[derive(Clone, Default)]
pub struct TestPlatform {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    now: AtomicI64,
    random: AtomicU64,
    logs: Mutex<Vec<String>>,
}

impl TestPlatform {
    pub fn at(millis: i64) -> Self {
        let platform = Self::default();
        platform.set_now(millis);
        platform
    }

    pub fn set_now(&self, millis: i64) {
        self.inner.now.store(millis, Ordering::SeqCst);
    }

    pub fn logs(&self) -> Vec<String> {
        self.inner.logs.lock().unwrap().clone()
    }

    pub fn clear_logs(&self) {
        self.inner.logs.lock().unwrap().clear();
    }
}

impl Platform for TestPlatform {
    fn now_millis(&self) -> i64 {
        self.inner.now.load(Ordering::SeqCst)
    }

    fn random_bytes(&self, buffer: &mut [u8]) {
        for chunk in buffer.chunks_mut(8) {
            // SplitMix64, which is enough to never make the same ID twice in a test.
            let random = &self.inner.random;
            let state = random.fetch_add(GOLDEN_GAMMA, Ordering::SeqCst);
            let mut z = state.wrapping_add(GOLDEN_GAMMA);
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            let bytes = z.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    fn log(&self, _level: LogLevel, message: &str) {
        self.inner.logs.lock().unwrap().push(message.to_owned());
    }
}

/// Makes requests to a local server the way a client does.
pub struct Client<F> {
    pub server: LocalServer<F, TestPlatform>,
    pub platform: TestPlatform,
}

impl Client<MemoryFileSystem> {
    /// A client of a local server on an empty vault folder in memory.
    pub fn in_memory(kind: ClientKind) -> (Self, MemoryFileSystem) {
        let fs = MemoryFileSystem::new();
        (Self::on(fs.clone(), TestPlatform::at(NOON), kind), fs)
    }
}

impl<F: FileSystem> Client<F> {
    pub fn on(fs: F, platform: TestPlatform, kind: ClientKind) -> Self {
        let server = LocalServer::new(fs, platform.clone(), kind);
        Self { server, platform }
    }

    pub fn request(&self, method: &str, path: &str) -> Call<'_, F> {
        let path: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        Call {
            client: self,
            request: LocalRequest::new(method, &path),
        }
    }

    /// Makes a request as the account of the token.
    pub fn get(&self, path: &str, token: &str) -> LocalResponse {
        self.request("GET", path).token(token).send()
    }

    /// Makes a request without a body as the account of the token.
    pub fn call(&self, method: &str, path: &str, token: &str) -> LocalResponse {
        self.request(method, path).token(token).send()
    }

    /// Makes a request with a JSON body as the account of the token.
    pub fn send(&self, method: &str, path: &str, token: &str, value: Value) -> LocalResponse {
        self.request(method, path).token(token).json(value).send()
    }

    /// Makes a request with a JSON body, as no account.
    pub fn send_anonymous(&self, method: &str, path: &str, value: Value) -> LocalResponse {
        self.request(method, path).json(value).send()
    }

    /// Downloads what is at the address, as a client does: the content of the file that the
    /// response names.
    pub fn download(&self, path: &str) -> Option<Vec<u8>> {
        let response = self.request("GET", path).send();
        let ResponseBody::File(path) = response.body else {
            return None;
        };
        let path: Vec<&str> = path.iter().map(String::as_str).collect();
        block_on(self.server.file_system().read(&path)).unwrap()
    }

    pub fn register(&self) {
        let registration = registration(EMAIL, PASSWORD_HASH);
        let path = "accounts/register/finish";
        let response = self.send_anonymous("POST", path, registration);
        assert_eq!(response.code, 200, "{:?}", response.json());
    }

    pub fn log_in(&self, email: &str, password_hash: &str) -> LocalResponse {
        let form = [
            ("grant_type", "password"),
            ("username", email),
            ("password", password_hash),
            ("client_id", "browser"),
        ];
        self.request("POST", "connect/token").form(&form).send()
    }

    /// Registers an account, logs in to it, and returns its access token and its ID.
    pub fn register_and_log_in(&self) -> (String, String) {
        self.register();
        let login = body(&self.log_in(EMAIL, PASSWORD_HASH));
        let token = login["access_token"].as_str().unwrap().to_owned();
        let user_id = user_id_of(&token);
        (token, user_id)
    }
}

/// A request that is being put together.
pub struct Call<'a, F> {
    client: &'a Client<F>,
    request: LocalRequest,
}

impl<F: FileSystem> Call<'_, F> {
    pub fn token(mut self, token: &str) -> Self {
        self.request.access_token = Some(token.to_owned());
        self
    }

    pub fn json(mut self, value: Value) -> Self {
        self.request.body = value.to_string().into_bytes();
        self
    }

    pub fn bytes(mut self, bytes: &[u8]) -> Self {
        self.request.body = bytes.to_vec();
        self
    }

    pub fn form(mut self, fields: &[(&str, &str)]) -> Self {
        self.request.form = to_map(fields);
        self
    }

    pub fn query(mut self, fields: &[(&str, &str)]) -> Self {
        self.request.query = to_map(fields);
        self
    }

    /// Sends the request, and stores its body where the response says, as a client does.
    pub fn try_send(self) -> Result<LocalResponse, IoError> {
        let server = &self.client.server;
        let response = block_on(server.handle(&self.request))?;
        if let Some(path) = &response.store_request_body_at {
            let path: Vec<&str> = path.iter().map(String::as_str).collect();
            block_on(server.file_system().write(&path, &self.request.body))?;
        }
        Ok(response)
    }

    pub fn send(self) -> LocalResponse {
        self.try_send().unwrap()
    }
}

fn to_map(fields: &[(&str, &str)]) -> HashMap<String, String> {
    let entries = fields
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()));
    entries.collect()
}

/// The JSON body of a response, or `null` if it has none.
pub fn body(response: &LocalResponse) -> Value {
    match &response.body {
        ResponseBody::Json(json) => serde_json::from_str(json).unwrap(),
        _ => Value::Null,
    }
}

/// The message of an error response.
pub fn message(response: &LocalResponse) -> String {
    body(response)["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// The ID of the account that the access token of a response to logging in is for.
pub fn logged_in_id(login: &Value) -> String {
    user_id_of(login["access_token"].as_str().unwrap())
}

/// The ID of the account that an access token is for.
pub fn user_id_of(token: &str) -> String {
    let payload = token.split('.').nth(1).unwrap();
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    claims["sub"].as_str().unwrap().to_owned()
}

/// The claims of an access token.
pub fn claims_of(token: &str) -> Value {
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

/// An access token in the shape of those of the local server, for the account.
pub fn token_for(user_id: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
    let payload = URL_SAFE_NO_PAD.encode(json!({"sub": user_id}).to_string());
    format!("{header}.{payload}.bG9jYWw")
}

/// What a client sends to register an account.
pub fn registration(email: &str, password_hash: &str) -> Value {
    json!({
        "email": email,
        "masterPasswordHint": "hint",
        "userAsymmetricKeys": {"publicKey": "publicKey", "encryptedPrivateKey": "2.privateKey"},
        "masterPasswordAuthentication": {
            "salt": email,
            "kdf": {"kdfType": 0, "iterations": 600000},
            "masterPasswordAuthenticationHash": password_hash,
        },
        "masterPasswordUnlock": {
            "salt": email,
            "kdf": {"kdfType": 0, "iterations": 600000},
            "masterKeyWrappedUserKey": USER_KEY,
        },
    })
}

/// The content of a file of the vault folder, as JSON.
pub fn read_json(fs: &MemoryFileSystem, path: &[&str]) -> Value {
    serde_json::from_slice(&fs.get(path).unwrap()).unwrap()
}

/// The `vault.json` of the account.
pub fn vault_file(fs: &MemoryFileSystem, user_id: &str) -> Value {
    read_json(fs, &[user_id, "vault.json"])
}

/// Replaces the `vault.json` of the account, as another device does.
pub fn replace_vault_file(fs: &MemoryFileSystem, user_id: &str, vault: &Value) {
    fs.put(&[user_id, "vault.json"], vault.to_string());
}

/// The path of an address that the local server handed out.
pub fn path_of(url: &str) -> String {
    url.trim_start_matches("https://vault.local.invalid/")
        .to_owned()
}
