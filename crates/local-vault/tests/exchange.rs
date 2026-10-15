//! Requests as the HTTP clients of the apps make them, and responses as they take them.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use common::*;
use futures::executor::block_on;
use local_vault::{
    BINARY_MEDIA_TYPE, BufferedResponse, ClientKind, FileSystem, HttpRequest, HttpResponse,
    JSON_MEDIA_TYPE, ResponseBody,
};
use serde_json::{Value, json};

const JSON: [(&str, &str); 1] = [("Content-Type", "application/json; charset=utf-8")];

const FORM: &str = "application/x-www-form-urlencoded;charset=UTF-8";

/// A request to the address, or to the path at the host of the local vault.
fn http(method: &str, address: &str, headers: &[(&str, &str)], body: &[u8]) -> HttpRequest {
    let headers = headers
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    let url = if address.contains("://") {
        address.to_owned()
    } else {
        format!("https://vault.local.invalid{address}")
    };
    HttpRequest {
        method: method.to_owned(),
        url,
        headers,
        body: body.to_vec(),
    }
}

fn send<F: FileSystem>(client: &Client<F>, request: HttpRequest) -> HttpResponse {
    block_on(client.server.handle_http(request)).unwrap()
}

fn send_buffered<F: FileSystem>(client: &Client<F>, request: HttpRequest) -> BufferedResponse {
    let response = block_on(client.server.handle_http_buffered(request));
    response.unwrap()
}

/// The JSON body of a response, or `null` if it has none.
fn json_body(response: &HttpResponse) -> Value {
    match &response.body {
        ResponseBody::Json(json) => serde_json::from_str(json).unwrap(),
        _ => Value::Null,
    }
}

#[test]
fn requests_are_answered_as_the_http_clients_of_the_apps_make_them() {
    let (client, _) = Client::in_memory(ClientKind::Browser);
    let registration = registration(EMAIL, PASSWORD_HASH).to_string();
    let form = [("content-type", FORM)];
    let password = "cGFzc3dvcmQtaGFzaA%3D%3D";
    let login = format!("grant_type=password&username=user%40example.com&password={password}");
    let register_path = "/identity/accounts/register/finish";
    let token_path = "/identity/connect/token";

    let request = http("POST", register_path, &JSON, registration.as_bytes());
    let registered = send(&client, request);
    let request = http("POST", token_path, &form, login.as_bytes());
    let logged_in = send(&client, request);
    let login = json_body(&logged_in);
    let bearer = format!("Bearer {}", login["access_token"].as_str().unwrap());
    let authorization = [("authorization", bearer.as_str())];
    let request = http("GET", "/api/sync", &authorization, &[]);
    let synced = send(&client, request);
    let request = http("POST", "/events/collect", &[], &[]);
    let collected = send(&client, request);

    assert_eq!(registered.status, 200);
    assert_eq!(registered.content_type, Some(JSON_MEDIA_TYPE));
    assert_eq!(logged_in.status, 200);
    assert_eq!(synced.status, 200);
    assert_eq!(json_body(&synced)["profile"]["email"], EMAIL);
    assert_eq!(collected.status, 200);
    assert_eq!(collected.content_type, None);
    assert_eq!(collected.body, ResponseBody::Empty);
}

#[test]
fn paths_are_taken_with_or_without_their_service_and_decoded() {
    let (client, _) = Client::in_memory(ClientKind::Android);
    let (token, _) = client.register_and_log_in();
    let bearer = format!("Bearer {token}");
    let authorization = [("Authorization", bearer.as_str())];
    let folder = client.send("POST", "folders", &token, json!({"name": "2.name"}));
    let id = body(&folder)["id"].as_str().unwrap().to_owned();
    let path = format!("/api/folders/{}", id.replace('-', "%2D"));

    let request = http("GET", &path, &authorization, &[]);
    let found = send(&client, request);
    let request = http("GET", "/sync", &authorization, &[]);
    let synced = send(&client, request);

    assert_eq!(found.status, 200);
    assert_eq!(json_body(&found)["id"], id.as_str());
    assert_eq!(synced.status, 200);
}

#[test]
fn the_content_of_an_attachment_is_left_to_the_client_or_stored_and_read_for_it() {
    let (client, fs) = Client::in_memory(ClientKind::Browser);
    let (token, user_id) = client.register_and_log_in();
    let cipher = body(&client.send("POST", "ciphers", &token, json!({"type": 1})));
    let cipher_id = cipher["id"].as_str().unwrap().to_owned();
    let path = format!("ciphers/{cipher_id}/attachment/v2");
    let upload = body(&client.send("POST", &path, &token, json!({})));
    let url = upload["url"].as_str().unwrap();
    let attachment_id = upload["attachmentId"].as_str().unwrap();

    let streamed = send(&client, http("PUT", url, &[], &[]));
    let stored = send_buffered(&client, http("PUT", url, &[], &[1, 2, 3]));
    let file = send(&client, http("GET", url, &[], &[]));
    let read = send_buffered(&client, http("GET", url, &[], &[]));

    let at = format!("{user_id}/attachments/{cipher_id}/{attachment_id}");
    let streamed_at = streamed.store_request_body_at.map(|path| path.join("/"));
    assert_eq!(streamed.status, 201);
    assert_eq!(streamed_at, Some(at));
    assert_eq!(stored.status, 201);
    let content = fs.get(&[&user_id, "attachments", &cipher_id, attachment_id]);
    assert_eq!(content, Some(vec![1, 2, 3]));
    assert_eq!(file.status, 200);
    assert_eq!(file.content_type, Some(BINARY_MEDIA_TYPE));
    assert!(matches!(file.body, ResponseBody::File(_)));
    assert_eq!(read.content_type, Some(BINARY_MEDIA_TYPE));
    assert_eq!(read.bytes, Some(vec![1, 2, 3]));
    assert_eq!(read.text, None);
}
