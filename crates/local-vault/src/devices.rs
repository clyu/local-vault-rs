//! The devices that share the vault of an account: which of them have a file in it, and retiring
//! one that is gone for good. Only the clients of the local vault ask for these, which is why their
//! paths are under `local-vault`, which a Bitwarden server does not have.

use serde_json::{Value, json};

use crate::date::format_date;
use crate::fs::FileSystem;
use crate::http::{
    bad_request, list_response, not_found_response, ok_response, unauthorized_response,
};
use crate::merge::GRACE_MILLIS;
use crate::platform::Platform;
use crate::server::{LocalServer, Outcome};
use crate::store::{Device, Retiring};

const THIS_DEVICE_MESSAGE: &str = "This device cannot be retired.";
const NOT_COMPLETE_MESSAGE: &str =
    "The file of the device has not fully come to this device yet. Try again later.";

impl<F: FileSystem, P: Platform> LocalServer<F, P> {
    /// Lists the devices that have a file in the vault of the account, this device among them
    /// whether or not it has one yet.
    pub(crate) async fn local_vault_devices(&self, user_id: &str) -> Outcome {
        let Some(devices) = self.reported(self.store.devices(user_id).await)? else {
            return Ok(unauthorized_response());
        };
        Ok(list_response(devices.iter().map(device_json).collect()))
    }

    /// Retires a device that is gone for good: this device takes its file over, and the vault is
    /// put together without that file (see `LocalVaultStore::retire_device`). Returns the device
    /// as it is listed then.
    pub(crate) async fn retire_local_vault_device(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Outcome {
        let now = self.platform.now_millis();
        let response = match self.store.retire_device(user_id, device_id, now).await? {
            Retiring::Retired(device) => ok_response(&device_json(&device)),
            Retiring::ThisDevice => bad_request(THIS_DEVICE_MESSAGE),
            Retiring::NotComplete => bad_request(NOT_COMPLETE_MESSAGE),
            Retiring::NoFile => not_found_response(),
        };
        Ok(response)
    }
}

/// A device as it is listed: its name and its type, as they are named for a Bitwarden server, if
/// its file says them, when it last changed the vault, and, if it was retired, when, and when its
/// directory is deleted, which the first device that tidies its file after that does.
fn device_json(device: &Device) -> Value {
    let date = |millis: Option<i64>| millis.map_or(Value::Null, |at| Value::from(format_date(at)));
    let removal = device.retired_at.map(|at| at.saturating_add(GRACE_MILLIS));
    let description = device.description.as_ref();
    json!({
        "object": "localVaultDevice",
        "id": device.id,
        "name": description.map(|description| description.name.as_str()),
        "type": description.map(|description| description.device_type),
        "isCurrentDevice": device.is_this_device,
        "revisionDate": date(device.revision_date),
        "retiredDate": date(device.retired_at),
        "removalDate": date(removal),
    })
}
