use near_sdk::serde::Serialize;
use near_sdk::serde_json::json;
use near_sdk::{log, AccountId, PublicKey};

pub const EVENT_STANDARD: &str = "tee-rng";
pub const EVENT_STANDARD_VERSION: &str = "1.0.0";

#[derive(Serialize)]
#[serde(
    crate = "near_sdk::serde",
    rename_all = "snake_case",
    tag = "event",
    content = "data"
)]
#[must_use = "Don't forget to `.emit()` this event"]
pub enum Event<'a> {
    WorkerRegistered {
        worker_id: &'a AccountId,
        public_key: &'a PublicKey,
        codehash: &'a String,
        checksum: &'a String,
    },
    Request {
        account_id: &'a AccountId,
        request_id: &'a u64,
        random_seed: &'a [u8],
    },
    Response {
        worker_id: &'a AccountId,
        request_id: &'a u64,
        random_number: &'a [u8],
    },
}

impl Event<'_> {
    pub fn emit(&self) {
        let json = json!(self);
        let event_json = json!({
            "standard": EVENT_STANDARD,
            "version": EVENT_STANDARD_VERSION,
            "event": json["event"],
            "data": [json["data"]]
        })
        .to_string();
        log!("EVENT_JSON:{}", event_json);
    }
}
