//! Requests as the HTTP client of a client has them, and responses that it turns into those of
//! its HTTP client. A client hands its requests over as they are, and what a request asks for is
//! worked out here, once for every client: which service it is for, whose request it is, and
//! what its form and its query hold.

use std::collections::HashMap;

use crate::fs::{FileSystem, IoError};
use crate::http::{LocalRequest, ResponseBody};
use crate::platform::Platform;
use crate::server::LocalServer;
use crate::vault::{ATTACHMENTS_PATH, LOCAL_VAULT_HOST};

/// The media type of a response with JSON.
pub const JSON_MEDIA_TYPE: &str = "application/json; charset=utf-8";

/// The media type of a response with the encrypted content of an attachment.
pub const BINARY_MEDIA_TYPE: &str = "application/octet-stream";

/// The first segments of the paths of the Bitwarden services, which the paths of the local
/// server are relative to. It answers for all of them.
const SERVICE_PREFIXES: [&str; 3] = ["api", "identity", "events"];

const FORM_MEDIA_TYPE: &str = "application/x-www-form-urlencoded";
const BEARER_PREFIX: &str = "Bearer ";

/// A request, as the HTTP client of a client would send it to a Bitwarden server.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpRequest {
    /// The HTTP method.
    pub method: String,
    /// The address, such as `https://vault.local.invalid/api/sync`. An address without a host,
    /// such as `/sync`, is taken as well.
    pub url: String,
    /// The headers, with their names in whatever case. The local server reads `Authorization`
    /// and `Content-Type`.
    pub headers: Vec<(String, String)>,
    /// The body. A client that streams the content of attachments leaves it out of a request
    /// to an address that [`streams_request_body`] is `true` for.
    pub body: Vec<u8>,
}

/// A response of the local server, as an HTTP client has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The media type of the body, or `None` if there is no body.
    pub content_type: Option<&'static str>,
    /// The body.
    pub body: ResponseBody,
    /// Where in the vault folder the client stores the body of the request before it gives
    /// this response: see [`LocalResponse::store_request_body_at`].
    ///
    /// [`LocalResponse::store_request_body_at`]: crate::LocalResponse::store_request_body_at
    pub store_request_body_at: Option<Vec<String>>,
}

/// A response of the local server with all of its body: JSON, or the content of a file of the
/// vault folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferedResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The media type of the body, or `None` if there is no body.
    pub content_type: Option<&'static str>,
    /// The JSON of the body, if that is the body.
    pub text: Option<String>,
    /// The encrypted content of an attachment, if that is the body.
    pub bytes: Option<Vec<u8>>,
}

impl<F: FileSystem, P: Platform> LocalServer<F, P> {
    /// Answers a request the way the Bitwarden server would, as [`LocalServer::handle`] does.
    ///
    /// The local server does not read the body of a request to an address that
    /// [`streams_request_body`] is `true` for: the response says where in the vault folder the
    /// client stores it, as it comes in. A file whose content is the body of the response is
    /// read by the client as well.
    pub async fn handle_http(&self, request: HttpRequest) -> Result<HttpResponse, IoError> {
        let response = self.handle(&to_local_request(request)).await?;
        Ok(HttpResponse {
            status: response.code,
            content_type: content_type(&response.body),
            body: response.body,
            store_request_body_at: response.store_request_body_at,
        })
    }

    /// Answers a request as [`LocalServer::handle_http`] does, for a client that has the content
    /// of an attachment in memory anyway: the body of the request is stored, and the file of
    /// the response read, before the next request is handled.
    ///
    /// Fails if the vault folder cannot be reached, which a file of a response that is gone is
    /// taken for.
    pub async fn handle_http_buffered(
        &self,
        request: HttpRequest,
    ) -> Result<BufferedResponse, IoError> {
        let (response, content) = self.handle_with_content(&to_local_request(request)).await?;
        let content_type = content_type(&response.body);
        let (text, bytes) = match response.body {
            ResponseBody::Empty => (None, None),
            ResponseBody::Json(json) => (Some(json), None),
            ResponseBody::File(_) => (None, content),
        };
        Ok(BufferedResponse {
            status: response.code,
            content_type,
            text,
            bytes,
        })
    }
}

/// Returns `true` if the address is one of the local vault, which no request may leave the
/// device for.
pub fn is_local_vault_url(url: &str) -> bool {
    split_url(url)
        .host
        .is_some_and(|host| host.eq_ignore_ascii_case(LOCAL_VAULT_HOST))
}

/// Returns `true` if the local server does not read the body of a request to the address, but
/// says where in the vault folder the client stores it: it is the encrypted content of an
/// attachment, which a client can write as it comes in.
pub fn streams_request_body(url: &str) -> bool {
    path_of(url)
        .first()
        .is_some_and(|segment| segment == ATTACHMENTS_PATH)
}

/// The request in the form that the local server answers.
fn to_local_request(request: HttpRequest) -> LocalRequest {
    let is_form = header(&request, "Content-Type")
        .is_some_and(|value| value.to_ascii_lowercase().contains(FORM_MEDIA_TYPE));
    let form = if is_form {
        parse_form(&String::from_utf8_lossy(&request.body))
    } else {
        HashMap::new()
    };
    let access_token = header(&request, "Authorization")
        .and_then(|value| value.strip_prefix(BEARER_PREFIX))
        .map(str::to_owned);
    let path = path_of(&request.url);
    let query = parse_form(split_url(&request.url).query);
    LocalRequest {
        method: request.method.to_ascii_uppercase(),
        path,
        access_token,
        form,
        query,
        body: request.body,
    }
}

/// The value of the header with the name, in whatever case, if there is one.
fn header<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
    let mut headers = request.headers.iter();
    let (_, value) = headers.find(|(key, _)| key.eq_ignore_ascii_case(name))?;
    Some(value.as_str())
}

/// The media type of the body of a response.
fn content_type(body: &ResponseBody) -> Option<&'static str> {
    match body {
        ResponseBody::Empty => None,
        ResponseBody::Json(_) => Some(JSON_MEDIA_TYPE),
        ResponseBody::File(_) => Some(BINARY_MEDIA_TYPE),
    }
}

/// The parts of an address that the local server looks at.
#[derive(Debug, PartialEq, Eq)]
struct Address<'a> {
    host: Option<&'a str>,
    path: &'a str,
    query: &'a str,
}

fn split_url(url: &str) -> Address<'_> {
    let url = url.split('#').next().unwrap_or_default();
    let (host, rest) = match url.split_once("://") {
        Some((_, rest)) => {
            let end = rest.find(['/', '?']).unwrap_or(rest.len());
            let (authority, rest) = rest.split_at_checked(end).unwrap_or((rest, ""));
            (Some(host_of(authority)), rest)
        }
        None => (None, url),
    };
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    Address { host, path, query }
}

/// The host of the authority of an address, without a user and without a port.
fn host_of(authority: &str) -> &str {
    let host_and_port = authority.rsplit_once('@').map_or(authority, |at| at.1);
    match host_and_port.strip_prefix('[') {
        // An IPv6 address.
        Some(bracketed) => bracketed.split(']').next().unwrap_or_default(),
        None => host_and_port.split(':').next().unwrap_or_default(),
    }
}

/// The decoded segments of the path of the address, relative to the service that it is for:
/// `sync` for `/api/sync`.
fn path_of(url: &str) -> Vec<String> {
    let mut segments: Vec<String> = split_url(url)
        .path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(decode_segment)
        .collect();
    let is_service = |first: &String| SERVICE_PREFIXES.contains(&first.as_str());
    if segments.first().is_some_and(is_service) {
        segments.remove(0);
    }
    segments
}

/// A segment of a path with what is percent-encoded in it decoded. A segment that is not text
/// once it is decoded is taken as it is, as the clients take it.
fn decode_segment(segment: &str) -> String {
    String::from_utf8(percent_decode(segment.as_bytes())).unwrap_or_else(|_| segment.to_owned())
}

/// The names and the values of a form, or of the query of an address. Of a name that is there
/// more than once, the last value counts.
fn parse_form(text: &str) -> HashMap<String, String> {
    text.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode_form_text(name), decode_form_text(value))
        })
        .collect()
}

/// A name or a value of a form, in which a `+` is a space.
fn decode_form_text(text: &str) -> String {
    let decoded = percent_decode(text.replace('+', " ").as_bytes());
    String::from_utf8_lossy(&decoded).into_owned()
}

/// The bytes with every `%` and two hexadecimal digits replaced by the byte that they stand
/// for. A `%` that is not followed by two of them stays.
fn percent_decode(mut bytes: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(bytes.len());
    while let [first, rest @ ..] = bytes {
        let escaped = match rest {
            [high, low, ..] if *first == b'%' => hex_digit(*high).zip(hex_digit(*low)),
            _ => None,
        };
        if let (Some((high, low)), [_, _, after @ ..]) = (escaped, rest) {
            decoded.push((high << 4) | low);
            bytes = after;
        } else {
            decoded.push(*first);
            bytes = rest;
        }
    }
    decoded
}

fn hex_digit(digit: u8) -> Option<u8> {
    let value = char::from(digit).to_digit(16)?;
    u8::try_from(value).ok()
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn request(url: &str, headers: &[(&str, &str)], body: &str) -> LocalRequest {
        let headers = headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        to_local_request(HttpRequest {
            method: "post".to_owned(),
            url: url.to_owned(),
            headers,
            body: body.as_bytes().to_vec(),
        })
    }

    #[test]
    fn addresses_are_split_into_what_the_local_server_looks_at() {
        let full = "https://user@Vault.Local.Invalid:443/api/sync?a=1#part";
        let ipv6 = "http://[::1]:8080/x";

        let expected = Address {
            host: Some("Vault.Local.Invalid"),
            path: "/api/sync",
            query: "a=1",
        };
        assert_eq!(split_url(full), expected);
        assert_eq!(split_url("https://vault.local.invalid").path, "");
        assert_eq!(split_url("https://vault.local.invalid?a").query, "a");
        assert_eq!(split_url(ipv6).host, Some("::1"));
        assert_eq!(split_url("/sync?b=2").host, None);
        assert_eq!(split_url("/sync?b=2").path, "/sync");
    }

    #[test]
    fn only_the_host_of_the_local_vault_is_one_of_the_local_vault() {
        let local = [
            "https://vault.local.invalid/api/sync",
            "https://VAULT.local.invalid:443",
        ];
        let other = [
            "https://api.bitwarden.com/sync",
            "https://vault.local.invalid.example.com/",
            "https://example.com/vault.local.invalid",
            "/sync",
        ];

        assert!(local.iter().all(|url| is_local_vault_url(url)));
        assert!(!other.iter().any(|url| is_local_vault_url(url)));
    }

    #[test]
    fn paths_are_relative_to_the_service_and_decoded() {
        let identity = "https://vault.local.invalid/identity/connect/token";
        let events = "https://vault.local.invalid/events/collect";
        let encoded = "https://vault.local.invalid/api/folders/a%2Db%20c/%E2%9C%93/%zz/%FF";

        assert_eq!(path_of(identity), ["connect", "token"]);
        assert_eq!(path_of(events), ["collect"]);
        assert_eq!(path_of("https://api.bitwarden.com/sync"), ["sync"]);
        assert_eq!(path_of("/api//sync/"), ["sync"]);
        // Only the first segment is the service.
        assert_eq!(path_of("/sync/api"), ["sync", "api"]);
        assert_eq!(path_of(encoded), ["folders", "a-b c", "✓", "%zz", "%FF"]);
    }

    #[test]
    fn only_the_content_of_attachments_is_streamed() {
        let content = "https://vault.local.invalid/attachments/user/cipher/attachment";
        let ciphers = "https://vault.local.invalid/api/ciphers";
        let named = "https://vault.local.invalid/api/ciphers/attachments";

        assert!(streams_request_body(content));
        assert!(!streams_request_body(ciphers));
        assert!(!streams_request_body(named));
    }

    #[test]
    fn a_form_is_read_by_its_media_type_and_a_token_from_its_header() {
        let url = "https://vault.local.invalid/identity/connect/token?x=1&y=a+b%2B&x=2&z";
        let form_type = "Application/X-WWW-Form-Urlencoded;charset=UTF-8";
        let headers = [
            ("content-type", form_type),
            ("AUTHORIZATION", "Bearer token"),
        ];
        let body = "username=user%40example.com&password=a%3D%3D+b";

        let form = request(url, &headers, body);
        let json = request(url, &[("Content-Type", "application/json")], "a=1");
        let basic = request(url, &[("Authorization", "Basic abc")], "");

        assert_eq!(form.method, "POST");
        assert_eq!(form.path, ["connect", "token"]);
        assert_eq!(form.access_token.as_deref(), Some("token"));
        assert_eq!(form.form["username"], "user@example.com");
        assert_eq!(form.form["password"], "a== b");
        assert_eq!(form.query["x"], "2");
        assert_eq!(form.query["y"], "a b+");
        assert_eq!(form.query["z"], "");
        assert!(json.form.is_empty());
        assert_eq!(json.body, b"a=1");
        assert_eq!(basic.access_token, None);
    }
}
