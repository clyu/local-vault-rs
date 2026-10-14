//! Reading and changing JSON as it comes. The local server never works on typed models, so that
//! fields that a newer client or SDK adds survive a round trip through it.
//!
//! `serde_json` is built with `preserve_order`, which keeps the fields in the order a file has
//! them, and with `arbitrary_precision`, which keeps every number with the digits that a file
//! writes it with: `1.0` stays `1.0`, and a large integer is not rounded. Only an exponent is
//! written with its sign, `1e+3` for `1e3`.

use base64::alphabet;
use base64::engine::{DecodePaddingMode, Engine, GeneralPurpose, GeneralPurposeConfig};
use serde::Serialize;
use serde_json::ser::{PrettyFormatter, Serializer};
use serde_json::{Map, Value};

/// A JSON object, with its fields in the order they were read or added in.
pub(crate) type JsonObject = Map<String, Value>;

/// The longest name of a file or a directory that the local vault uses.
const MAX_SEGMENT_LENGTH: usize = 128;

/// What JSON is indented with in a file of the vault.
const INDENT: &[u8] = b"    ";

/// Base64 that is decoded with or without its padding, and with the bits that the last character
/// has left over, as the platforms that wrote the earlier vaults decode it.
const BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// The URL-safe Base64 of tokens, which is written without padding.
const BASE64_URL: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// Returns `true` if the name can be used as the name of a file or a directory in the vault
/// folder without leaving the directory that it is placed in: it is made of 1 to 128 ASCII
/// letters, digits, `-` and `_`.
pub fn is_safe_segment(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_SEGMENT_LENGTH
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Returns `true` if both are the same text in whatever case, which is how IDs and the names of
/// fields are compared.
pub(crate) fn eq_ignore_case(a: &str, b: &str) -> bool {
    a == b || a.to_lowercase() == b.to_lowercase()
}

/// Returns the value for the key, falling back to a key that only differs in case. The server
/// API is not consistent about the case of its field names.
pub(crate) fn element<'a>(object: &'a JsonObject, key: &str) -> Option<&'a Value> {
    object.get(key).or_else(|| {
        object
            .iter()
            .find(|(name, _)| eq_ignore_case(name, key))
            .map(|(_, value)| value)
    })
}

/// Returns the value as an object, or an empty object if it is not one.
pub(crate) fn into_object(value: Value) -> JsonObject {
    match value {
        Value::Object(object) => object,
        _ => JsonObject::new(),
    }
}

/// Returns the object for the key, or `None` if there is no object for it.
pub(crate) fn obj<'a>(object: &'a JsonObject, key: &str) -> Option<&'a JsonObject> {
    element(object, key).and_then(Value::as_object)
}

/// Returns the objects in the array for the key, or none if there is no array for it.
pub(crate) fn objects(object: &JsonObject, key: &str) -> Vec<JsonObject> {
    let values = element(object, key).and_then(Value::as_array);
    let objects = values.into_iter().flatten().filter_map(Value::as_object);
    objects.cloned().collect()
}

/// Returns the string for the key, or `None` if there is no string for it.
pub(crate) fn string<'a>(object: &'a JsonObject, key: &str) -> Option<&'a str> {
    element(object, key).and_then(Value::as_str)
}

/// Returns the strings in the array for the key, or none if there is no array for it.
pub(crate) fn strings(object: &JsonObject, key: &str) -> Vec<String> {
    let values = element(object, key).and_then(Value::as_array);
    let strings = values.into_iter().flatten().filter_map(Value::as_str);
    strings.map(str::to_owned).collect()
}

/// Returns the string or the number for the key as text, the number as it is written, or `None`
/// if there is neither.
pub(crate) fn text(object: &JsonObject, key: &str) -> Option<String> {
    match element(object, key)? {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// Returns the integer for the key, or `None` if there is none.
///
/// Only a number that is written as an integer is one: not `1.0`, not `1e3`, and not the string
/// `"1"`.
pub(crate) fn int(object: &JsonObject, key: &str) -> Option<i64> {
    element(object, key).and_then(Value::as_number)?.as_i64()
}

/// Returns the value of an optional integer for the key: the integer, or `null`.
pub(crate) fn int_or_null(object: Option<&JsonObject>, key: &str) -> Value {
    object
        .and_then(|object| int(object, key))
        .map_or(Value::Null, Value::from)
}

/// Returns a copy of the object with the fields added or replaced. A field that it has keeps
/// its place.
pub(crate) fn with_fields<const N: usize>(
    object: &JsonObject,
    fields: [(&str, Value); N],
) -> JsonObject {
    let mut copy = object.clone();
    for (key, value) in fields {
        copy.insert(key.to_owned(), value);
    }
    copy
}

/// Returns a copy of the object without the fields, the others in the order they were in.
pub(crate) fn without_fields(object: &JsonObject, keys: &[&str]) -> JsonObject {
    let mut copy = object.clone();
    for key in keys {
        copy.shift_remove(*key);
    }
    copy
}

/// The value of an optional string: the string, or `null`.
pub(crate) fn string_or_null(value: Option<&str>) -> Value {
    value.map_or(Value::Null, |text| Value::String(text.to_owned()))
}

/// Parses a complete JSON document from bytes that are meant to be UTF-8, the way a file of the
/// vault and the body of a request are read: bytes that are not UTF-8 are replaced, and a byte
/// order mark at the start is left out.
pub(crate) fn parse(bytes: &[u8]) -> Option<Value> {
    let text = String::from_utf8_lossy(bytes);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    serde_json::from_str(text).ok()
}

/// Writes the value the way the files of the vault are written: as UTF-8, indented by four
/// spaces.
pub(crate) fn to_pretty_bytes(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut serializer =
        Serializer::with_formatter(&mut bytes, PrettyFormatter::with_indent(INDENT));
    // Writing a value to memory cannot fail, so there is nothing to handle.
    let _ = value.serialize(&mut serializer);
    bytes
}

/// Returns the form of an email address that accounts are compared by: without the whitespace
/// around it, in lower case.
pub(crate) fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Returns `true` if the text has nothing but whitespace.
pub(crate) fn is_blank(text: &str) -> bool {
    text.trim().is_empty()
}

pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    BASE64.encode(bytes)
}

/// Decodes Base64, or returns `None` if the text is not Base64.
pub(crate) fn base64_decode(text: &str) -> Option<Vec<u8>> {
    BASE64.decode(text).ok()
}

pub(crate) fn base64_url_encode(bytes: &[u8]) -> String {
    BASE64_URL.encode(bytes)
}

/// Decodes the URL-safe form of Base64 to text, or returns `None` if it is not that.
pub(crate) fn base64_url_decode(text: &str) -> Option<String> {
    let bytes = BASE64_URL.decode(text).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn object(value: Value) -> JsonObject {
        value.as_object().cloned().unwrap()
    }

    #[test]
    fn safe_segments_are_short_names_of_letters_digits_hyphens_and_underscores() {
        let uuid = "11111111-2222-4333-8444-555555555555";
        let longest: &str = &"x".repeat(128);
        let too_long: &str = &"x".repeat(129);

        for name in ["a", "A-1_b", uuid, longest] {
            assert!(is_safe_segment(name), "{name}");
        }
        for name in ["", ".", "..", "a/b", "a\\b", "a.b", "ä", "a\n", too_long] {
            assert!(!is_safe_segment(name), "{name}");
        }
    }

    #[test]
    fn fields_are_found_in_whatever_case() {
        let value = object(json!({"MasterPasswordHash": "a", "key": "b", "KEY": "c"}));

        assert_eq!(string(&value, "masterPasswordHash"), Some("a"));
        // A field in the exact case comes first.
        assert_eq!(string(&value, "KEY"), Some("c"));
        assert_eq!(string(&value, "key"), Some("b"));
        assert_eq!(string(&value, "missing"), None);
    }

    #[test]
    fn integers_are_numbers_that_are_written_as_integers() {
        let content = r#"{"a": 1, "b": -2, "c": 1.0, "d": 1e3, "e": "1", "f": null, "g": 1e2}"#;
        let value = object(serde_json::from_str(content).unwrap());
        let large = object(serde_json::from_str(r#"{"a": 9007199254740993}"#).unwrap());

        assert_eq!(int(&value, "a"), Some(1));
        assert_eq!(int(&value, "b"), Some(-2));
        assert_eq!(int(&value, "c"), None);
        assert_eq!(int(&value, "d"), None);
        assert_eq!(int(&value, "e"), None);
        assert_eq!(int(&value, "f"), None);
        assert_eq!(int(&value, "g"), None);
        assert_eq!(int(&large, "a"), Some(9_007_199_254_740_993));
    }

    #[test]
    fn numbers_are_written_back_with_the_digits_that_they_were_read_with() {
        let content = r#"{"a":1.0,"b":1e3,"c":9007199254740993,"d":0.1000}"#;
        let expected = r#"{"a":1.0,"b":1e+3,"c":9007199254740993,"d":0.1000}"#;

        let value: Value = serde_json::from_str(content).unwrap();
        let fields = value.as_object().unwrap();

        assert_eq!(value.to_string(), expected);
        assert_eq!(text(fields, "a").as_deref(), Some("1.0"));
    }

    #[test]
    fn fields_keep_their_order() {
        let value = object(json!({"b": 1, "a": 2, "c": 3}));

        let changed = with_fields(
            &without_fields(&value, &["a"]),
            [("b", json!(4)), ("d", json!(5))],
        );

        let expected = r#"{"b":4,"c":3,"d":5}"#;
        assert_eq!(Value::Object(changed).to_string(), expected);
    }

    #[test]
    fn a_byte_order_mark_and_bytes_that_are_not_utf8_do_not_keep_a_file_from_being_read() {
        assert_eq!(parse(b"\xef\xbb\xbf{\"a\":1}"), Some(json!({"a": 1})));
        assert_eq!(parse(b"{\"a\":\"\xff\"}"), Some(json!({"a": "\u{fffd}"})));
        assert_eq!(parse(b""), None);
        assert_eq!(parse(b"{\"a\":"), None);
    }

    #[test]
    fn files_are_indented_by_four_spaces() {
        let bytes = to_pretty_bytes(&json!({"format": "bitwarden-local-vault", "version": 1}));

        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "{\n    \"format\": \"bitwarden-local-vault\",\n    \"version\": 1\n}"
        );
    }

    #[test]
    fn base64_is_decoded_with_or_without_padding() {
        assert_eq!(base64_decode("YWI=").unwrap(), b"ab");
        assert_eq!(base64_decode("YWI").unwrap(), b"ab");
        assert_eq!(base64_decode("***"), None);
        let encoded = base64_url_encode("ü?>".as_bytes());
        assert_eq!(base64_url_decode(&encoded).as_deref(), Some("ü?>"));
    }

    #[test]
    fn emails_are_compared_without_case_and_surrounding_whitespace() {
        assert_eq!(normalize_email(" Test@Example.COM \n"), "test@example.com");
    }
}
