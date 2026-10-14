use std::collections::HashMap;

use serde_json::{Value, json};

use crate::json::{self, JsonObject};

pub(crate) const HTTP_OK: u16 = 200;
pub(crate) const HTTP_CREATED: u16 = 201;
pub(crate) const HTTP_BAD_REQUEST: u16 = 400;
pub(crate) const HTTP_UNAUTHORIZED: u16 = 401;
pub(crate) const HTTP_NOT_FOUND: u16 = 404;
pub(crate) const HTTP_TOO_MANY_REQUESTS: u16 = 429;
pub(crate) const HTTP_INTERNAL_ERROR: u16 = 500;

const UNSUPPORTED_MESSAGE: &str =
    "This feature needs a Bitwarden server and is not available with a local vault.";
const INVALID_REQUEST_MESSAGE: &str = "The request is not valid.";

/// A request to the local server, as a client would have sent it to a Bitwarden server.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalRequest {
    /// The HTTP method, in upper case.
    pub method: String,
    /// The decoded segments of the path, relative to the service that the request is for:
    /// `sync`, not `api/sync`.
    pub path: Vec<String>,
    /// The bearer token that the request was made with, if any.
    pub access_token: Option<String>,
    /// The fields of the body, if it is a form.
    pub form: HashMap<String, String>,
    /// The parameters of the query of the address.
    pub query: HashMap<String, String>,
    /// The body. The body of a request for the content of an attachment is not read: see
    /// [`LocalResponse::store_request_body_at`].
    pub body: Vec<u8>,
}

impl LocalRequest {
    /// A request with the method and the path, and nothing else.
    pub fn new(method: &str, path: &[&str]) -> Self {
        Self {
            method: method.to_owned(),
            path: path.iter().map(|segment| (*segment).to_owned()).collect(),
            ..Self::default()
        }
    }

    /// The field of the form, if there is one.
    pub(crate) fn form_field(&self, key: &str) -> Option<&str> {
        self.form.get(key).map(String::as_str)
    }

    /// The body as a JSON object, which is empty if the body is empty or not an object. Fails
    /// if the body is not JSON.
    pub(crate) fn json_body(&self) -> Result<JsonObject, InvalidRequest> {
        let text = String::from_utf8_lossy(&self.body);
        if json::is_blank(&text) {
            return Ok(JsonObject::new());
        }
        match json::parse(text.as_bytes()) {
            Some(Value::Object(body)) => Ok(body),
            Some(_) => Ok(JsonObject::new()),
            None => Err(InvalidRequest),
        }
    }
}

/// The body of a request is not what the request needs it to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvalidRequest;

/// The body of a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseBody {
    /// No body.
    Empty,
    /// JSON, for `application/json`.
    Json(String),
    /// The content of the file at the path of the vault folder, for `application/octet-stream`.
    /// The file exists.
    File(Vec<String>),
}

/// A response of the local server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalResponse {
    /// The HTTP status code.
    pub code: u16,
    /// The body.
    pub body: ResponseBody,
    /// Where in the vault folder the body of the request has to be stored before the client is
    /// given this response. It is the content of an attachment, which the local server leaves
    /// to the client so that the client can write it as it comes in. A client that fails to
    /// store it fails the request as a request that did not reach its server.
    pub store_request_body_at: Option<Vec<String>>,
}

impl LocalResponse {
    /// The JSON of the body, if it has some.
    pub fn json(&self) -> Option<&str> {
        match &self.body {
            ResponseBody::Json(json) => Some(json.as_str()),
            _ => None,
        }
    }
}

/// Returns `true` if the text is a UUID, in whatever case.
pub(crate) fn is_uuid(text: &str) -> bool {
    text.len() == 36 && text.char_indices().all(|(i, c)| is_uuid_char(i, c))
}

fn is_uuid_char(index: usize, c: char) -> bool {
    match index {
        8 | 13 | 18 | 23 => c == '-',
        _ => c.is_ascii_hexdigit(),
    }
}

/// A successful response with the JSON as its body.
pub(crate) fn json_response(value: &Value, code: u16) -> LocalResponse {
    LocalResponse {
        code,
        body: ResponseBody::Json(value.to_string()),
        store_request_body_at: None,
    }
}

/// A response with `200 OK` and the JSON as its body.
pub(crate) fn ok_response(value: &Value) -> LocalResponse {
    json_response(value, HTTP_OK)
}

/// A successful response without a body.
pub(crate) fn empty_response(code: u16) -> LocalResponse {
    LocalResponse {
        code,
        body: ResponseBody::Empty,
        store_request_body_at: None,
    }
}

/// A response with `200 OK` and without a body.
pub(crate) fn ok_empty_response() -> LocalResponse {
    empty_response(HTTP_OK)
}

/// An error response in the shape that the Bitwarden API reports errors in.
pub(crate) fn error_response(code: u16, message: &str) -> LocalResponse {
    let error = json!({"message": message, "validationErrors": null, "object": "error"});
    json_response(&error, code)
}

/// The response for a request that cannot be done, for the reason that the message gives.
pub(crate) fn bad_request(message: &str) -> LocalResponse {
    error_response(HTTP_BAD_REQUEST, message)
}

/// A response with `200 OK` and the encrypted content of the file at the path as its body.
pub(crate) fn file_response(path: Vec<String>) -> LocalResponse {
    LocalResponse {
        code: HTTP_OK,
        body: ResponseBody::File(path),
        store_request_body_at: None,
    }
}

/// The response for something that does not exist.
pub(crate) fn not_found_response() -> LocalResponse {
    error_response(HTTP_NOT_FOUND, "Resource not found.")
}

/// The response for a request that is not valid.
pub(crate) fn invalid_request_response() -> LocalResponse {
    error_response(HTTP_BAD_REQUEST, INVALID_REQUEST_MESSAGE)
}

/// The response for a feature that cannot work without a Bitwarden server.
pub(crate) fn unsupported_response() -> LocalResponse {
    error_response(HTTP_BAD_REQUEST, UNSUPPORTED_MESSAGE)
}

/// The response for a request that needs an account and is not made as one.
pub(crate) fn unauthorized_response() -> LocalResponse {
    error_response(HTTP_UNAUTHORIZED, "Unauthorized.")
}

/// A page of a list, which is the only one.
pub(crate) fn list_response(data: Vec<Value>) -> LocalResponse {
    let list = json!({"data": data, "continuationToken": null, "object": "list"});
    ok_response(&list)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids_are_recognized_in_whatever_case() {
        assert!(is_uuid("11111111-2222-4333-8444-55555555555A"));
        assert!(is_uuid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
        assert!(!is_uuid("1111111122224333844455555555555a"));
        assert!(!is_uuid("11111111-2222-4333-8444-55555555555g"));
        assert!(!is_uuid("admin"));
    }

    #[test]
    fn the_body_is_json_or_not_valid() {
        let mut request = LocalRequest::new("POST", &["folders"]);
        assert_eq!(request.json_body(), Ok(JsonObject::new()));

        request.body = b" [1] ".to_vec();
        assert_eq!(request.json_body(), Ok(JsonObject::new()));

        request.body = b"{not json".to_vec();
        assert_eq!(request.json_body(), Err(InvalidRequest));

        request.body = br#"{"name": "a"}"#.to_vec();
        let body = request.json_body().unwrap_or_default();
        assert_eq!(json::string(&body, "name"), Some("a"));
    }
}
