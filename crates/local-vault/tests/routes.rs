//! What the local server answers, what it refuses, and how it fails.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use std::sync::atomic::{AtomicBool, Ordering};

use common::*;
use futures::executor::block_on;
use futures::future::join_all;
use local_vault::{
    ClientKind, FLAGS_THAT_MUST_BE_OFF, FileSystem, IoError, MemoryFileSystem, is_answered,
};
use serde_json::json;

fn browser() -> (Client<MemoryFileSystem>, MemoryFileSystem) {
    Client::in_memory(ClientKind::Browser)
}

#[test]
fn requests_that_there_is_nothing_to_do_for_succeed() {
    let (client, _) = browser();
    let (token, _) = client.register_and_log_in();
    let empty_list = json!({"data": [], "continuationToken": null, "object": "list"});

    let known_device = client.request("GET", "devices/knowndevice").send();
    assert_eq!(body(&known_device), json!(false));
    assert_eq!(client.request("POST", "collect").send().code, 200);
    let clicked = "accounts/register/verification-email-clicked";
    assert_eq!(client.request("POST", clicked).send().code, 200);
    let unassigned = client.get("ciphers/has-unassigned-ciphers", &token);
    assert_eq!(body(&unassigned), json!(false));
    let lists = [
        "auth-requests",
        "auth-requests/pending",
        "devices",
        "tasks",
        "notifications",
    ];
    for path in lists {
        assert_eq!(body(&client.get(path, &token)), empty_list, "{path}");
    }
    let push_token = client.call("PUT", "devices/identifier/id/token", &token);
    assert_eq!(push_token.code, 200);
}

#[test]
fn no_feature_flags_are_reported() {
    let (client, _) = browser();

    let config = body(&client.request("GET", "config").send());

    assert_eq!(config["featureStates"], json!({}));
    assert_eq!(config["object"], "config");
    assert_eq!(config["server"], json!(null));
}

#[test]
fn features_that_need_a_server_are_reported_as_not_available() {
    let (client, _) = browser();
    let (token, _) = client.register_and_log_in();
    let unsupported = json!({
        "message": UNSUPPORTED_MESSAGE,
        "validationErrors": null,
        "object": "error",
    });
    let share = format!("ciphers/{UNKNOWN_ID}/share");
    let requests = [
        ("GET", "sends"),
        ("POST", "sends"),
        ("GET", "organizations/id/policies"),
        ("POST", "two-factor/get-authenticator"),
        ("POST", "accounts/premium"),
        ("PUT", share.as_str()),
        // Not an item with the ID "admin": what an organization does with its items.
        ("DELETE", "ciphers/admin"),
        ("PUT", "ciphers/delete-admin"),
        ("GET", "ciphers/organization-details"),
        // Not an item either: the ID of an item is a UUID.
        ("PUT", "ciphers/mockId/archive"),
    ];

    for (method, path) in requests {
        let response = client.call(method, path, &token);

        assert_eq!(response.code, 400, "{method} {path}");
        assert_eq!(body(&response), unsupported, "{method} {path}");
    }
}

#[test]
fn what_is_answered_is_known_without_making_the_request() {
    let (client, _) = browser();
    let (token, _) = client.register_and_log_in();
    let item = format!("ciphers/{UNKNOWN_ID}");
    let archive = format!("ciphers/{UNKNOWN_ID}/archive");
    let share = format!("ciphers/{UNKNOWN_ID}/share");
    let requests = [
        ("GET", "sync"),
        ("POST", "connect/token"),
        ("GET", item.as_str()),
        ("PUT", archive.as_str()),
        ("PUT", "devices/identifier/id/token"),
        ("GET", "local-vault/devices"),
        ("POST", "local-vault/devices/device-x/retire"),
        ("PUT", "attachments/a/b/c"),
        ("GET", "sends"),
        ("PUT", share.as_str()),
        ("PUT", "ciphers/mockId/archive"),
        ("DELETE", "ciphers/admin"),
        ("DELETE", "attachments/a/b/c"),
        ("GET", "accounts/webauthn/assertion-options"),
    ];

    for (method, path) in requests {
        let parts: Vec<&str> = path.split('/').collect();
        let response = client.call(method, path, &token);
        let refused = message(&response) == UNSUPPORTED_MESSAGE;

        assert_eq!(is_answered(method, &parts), !refused, "{method} {path}");
    }
}

#[test]
fn every_feature_flag_that_has_to_be_off_is_listed_once_for_its_clients() {
    let rules = FLAGS_THAT_MUST_BE_OFF;
    let keys: Vec<&str> = rules.iter().map(|rule| rule.key).collect();
    let mut unique = keys.clone();
    unique.sort_unstable();
    unique.dedup();

    assert_eq!(unique.len(), keys.len());
    assert!(rules.iter().all(|rule| !rule.clients.is_empty()));
}

#[test]
fn what_is_refused_is_logged_without_what_identifies_an_item_or_an_account() {
    let (client, _) = browser();
    let (token, user_id) = client.register_and_log_in();

    let share = format!("ciphers/{UNKNOWN_ID}/share");
    let action = format!("ciphers/{user_id}/mockAction");
    client.call("PUT", &share, &token);
    client.call("PUT", &action, &token);
    client.call("POST", "sends/user@example.com", &token);
    client.get("sync", &token);

    let refused = [
        "Local server refused: PUT ciphers/*/share",
        "Local server refused: PUT ciphers/*/*",
        "Local server refused: POST sends/*",
    ];
    assert_eq!(client.platform.logs(), refused);
}

#[test]
fn a_request_that_there_is_no_route_for_is_refused_with_or_without_a_token() {
    let (client, _) = browser();
    client.register_and_log_in();

    // The identity service is asked without a token, also for what there is no route for.
    let options = "accounts/webauthn/assertion-options";
    let refused = client.request("GET", options).send();
    let with_wrong_token = client.call("POST", "sends", "not.a.token");
    let unauthorized = client.request("GET", "sync").send();

    for response in [refused, with_wrong_token] {
        assert_eq!(response.code, 400);
        assert_eq!(message(&response), UNSUPPORTED_MESSAGE);
    }
    // A request that there is a route for needs the token of an account, as before.
    assert_eq!(unauthorized.code, 401);
}

#[test]
fn a_request_that_is_not_valid_is_answered_with_an_error() {
    let (client, _) = browser();
    let (token, _) = client.register_and_log_in();

    let request = client.request("POST", "folders").token(&token);
    let response = request.bytes(b"{not json").send();

    assert_eq!(response.code, 400);
    assert_eq!(message(&response), "The request is not valid.");
}

#[test]
fn requests_are_handled_one_at_a_time() {
    let (client, fs) = browser();
    let (token, user_id) = client.register_and_log_in();
    let requests: Vec<_> = ["a", "b", "c", "d", "e"]
        .into_iter()
        .map(|name| {
            let mut request = local_vault::LocalRequest::new("POST", &["folders"]);
            request.access_token = Some(token.clone());
            request.body = json!({"name": name}).to_string().into_bytes();
            request
        })
        .collect();

    let handled = requests.iter().map(|request| client.server.handle(request));
    let responses = block_on(join_all(handled));

    assert!(responses.iter().all(|response| response.is_ok()));
    let folders = &vault_file(&fs, &user_id)["sync"]["folders"];
    let folders = folders.as_array().unwrap();
    let names: Vec<_> = folders.iter().map(|f| f["name"].clone()).collect();
    assert_eq!(names, ["a", "b", "c", "d", "e"]);
}

#[test]
fn a_vault_folder_that_cannot_be_reached_fails_the_request_until_it_can_be_again() {
    let fs = MemoryFileSystem::new();
    let flaky = Flaky {
        fs: fs.clone(),
        is_down: AtomicBool::new(false),
    };
    let client = Client::on(flaky, TestPlatform::at(NOON), ClientKind::Browser);
    let (token, _) = client.register_and_log_in();

    let is_down = &client.server.file_system().is_down;
    is_down.store(true, Ordering::SeqCst);
    let failed = client.request("GET", "sync").token(&token).try_send();
    is_down.store(false, Ordering::SeqCst);
    let succeeded = client.request("GET", "sync").token(&token).try_send();

    let gone = IoError::new("The vault folder is gone.");
    assert_eq!(failed.unwrap_err(), gone);
    assert_eq!(succeeded.unwrap().code, 200);
}

#[test]
fn the_android_app_is_told_the_password_hint_the_way_it_shows_it() {
    let (client, _) = Client::in_memory(ClientKind::Android);
    client.register();

    let body = json!({"email": EMAIL});
    let path = "accounts/password-hint";
    let response = client.send_anonymous("POST", path, body);

    assert_eq!(response.code, 429);
    assert_eq!(message(&response), "Your master password hint: hint");
}

/// A vault folder that can be taken away, as a drive that is unplugged.
struct Flaky {
    fs: MemoryFileSystem,
    is_down: AtomicBool,
}

impl Flaky {
    fn check(&self) -> Result<(), IoError> {
        if self.is_down.load(Ordering::SeqCst) {
            Err(IoError::new("The vault folder is gone."))
        } else {
            Ok(())
        }
    }
}

impl FileSystem for Flaky {
    async fn list(&self, directory: &[&str]) -> Result<Vec<String>, IoError> {
        self.check()?;
        self.fs.list(directory).await
    }

    async fn exists(&self, path: &[&str]) -> Result<bool, IoError> {
        self.check()?;
        self.fs.exists(path).await
    }

    async fn read(&self, path: &[&str]) -> Result<Option<Vec<u8>>, IoError> {
        self.check()?;
        self.fs.read(path).await
    }

    async fn write(&self, path: &[&str], content: &[u8]) -> Result<(), IoError> {
        self.check()?;
        self.fs.write(path, content).await
    }

    async fn rename(&self, path: &[&str], new_name: &str) -> Result<bool, IoError> {
        self.check()?;
        self.fs.rename(path, new_name).await
    }

    async fn delete(&self, path: &[&str]) -> Result<bool, IoError> {
        self.check()?;
        self.fs.delete(path).await
    }
}
