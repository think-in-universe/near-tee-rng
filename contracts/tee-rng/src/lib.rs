use dcap_qvl::{verify, QuoteCollateralV3};
use hex::{decode, encode};
use near_sdk::{
    assert_one_yocto,
    env::{self, block_timestamp},
    log, near, require,
    store::{IterableMap, IterableSet},
    AccountId, BorshStorageKey, CryptoHash, Gas, GasWeight, PanicOnDefault, PromiseError,
    PromiseOrValue, PublicKey,
};

use crate::events::*;

mod admin;
mod collateral;
mod events;
mod upgrade;
mod view;

// Register used to receive data id from `promise_await_data`.
const DATA_ID_REGISTER: u64 = 0;

// Prepaid gas for a `on_received_response` call
const ON_RECEIVED_RESPONSE_CALL_GAS: Gas = Gas::from_tgas(5);

#[near]
#[derive(BorshStorageKey)]
pub enum Prefix {
    ApprovedCodeHashes,
    WorkerByAccountId,
    PendingRequests,
}

#[near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct Worker {
    checksum: String,
    codehash: String,
    public_key: PublicKey,
}

/// The index into calling the YieldResume feature of NEAR. This will allow to resume
/// a yield call after the contract has been called back via this index.
#[derive(Debug, Clone)]
#[near(serializers=[borsh, json])]
pub struct YieldIndex {
    pub data_id: CryptoHash,
}

#[near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct Request {
    request_id: u64,
    random_seed: Vec<u8>,
    yield_index: YieldIndex,
}

#[near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct Response {
    request_id: u64,
    random_number: Vec<u8>,
    signature: Vec<u8>,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    owner_id: AccountId,
    approved_codehashes: IterableSet<String>,
    worker_by_account_id: IterableMap<AccountId, Worker>,
    pending_requests: IterableMap<u64, Request>,
    last_request_id: u64,
}

#[near]
impl Contract {
    #[init]
    #[private]
    pub fn new(owner_id: AccountId) -> Self {
        Self {
            owner_id,
            approved_codehashes: IterableSet::new(Prefix::ApprovedCodeHashes),
            worker_by_account_id: IterableMap::new(Prefix::WorkerByAccountId),
            pending_requests: IterableMap::new(Prefix::PendingRequests),
            last_request_id: 0,
        }
    }

    #[payable]
    pub fn register_worker(
        &mut self,
        quote_hex: String,
        collateral: String,
        checksum: String,
        tcb_info: String,
        skip_verify: Option<bool>,
    ) {
        assert_one_yocto();

        let skip_verify = skip_verify.unwrap_or(false);
        let public_key = env::signer_account_pk();
        let codehash = if !skip_verify {
            let collateral = collateral::get_collateral(collateral);
            let quote = decode(quote_hex).unwrap();
            let now = block_timestamp() / 1000000000;
            let result = verify::verify(&quote, &collateral, now).expect("Report is not verified");
            let report = result.report.as_td10().unwrap();
            let rtmr3 = encode(report.rt_mr3);
    
            // verify the signer public key is the same as the one included in the report data
            let report_data = encode(report.report_data);
            let public_key = env::signer_account_pk();
            let public_key_str: String = (&public_key).into();
            // pad the public key hex with 0 to 128 characters
            let public_key_hex = format!("{:0>128}", encode(public_key_str));
            require!(
                public_key_hex == report_data,
                format!(
                    "Invalid public key: {} v.s. {}",
                    public_key_hex, report_data
                )
            );

            // only allow workers with approved code hashes to register
            let codehash = collateral::verify_codehash(tcb_info, rtmr3);
            self.assert_approved_codehash(&codehash);

            log!("verify result: {:?}", result);

            codehash
        } else {
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string()
        };

        let worker_id = env::predecessor_account_id();

        self.worker_by_account_id.insert(
            worker_id.clone(),
            Worker {
                checksum: checksum.clone(),
                codehash: codehash.clone(),
                public_key: public_key.clone(),
            },
        );

        Event::WorkerRegistered {
            worker_id: &worker_id,
            public_key: &public_key,
            codehash: &codehash,
            checksum: &checksum,
        }
        .emit();
    }

    /// Request a random number
    pub fn request(&mut self) {
        let request_id = self.last_request_id + 1;
        self.last_request_id = request_id;

        let promise_index = env::promise_yield_create(
            "on_received_response",
            &serde_json::to_vec(&(&request_id,)).unwrap(),
            ON_RECEIVED_RESPONSE_CALL_GAS,
            GasWeight(0),
            DATA_ID_REGISTER,
        );

        // Store the request in the contract's local state
        let data_id: CryptoHash = env::read_register(DATA_ID_REGISTER)
            .expect("read_register failed")
            .try_into()
            .expect("conversion to CryptoHash failed");

        self.pending_requests.insert(
            request_id,
            Request {
                request_id,
                random_seed: env::random_seed(),
                yield_index: YieldIndex { data_id },
            },
        );

        env::promise_return(promise_index);
    }

    /// A worker inside TEE will call the function with a response to the request
    pub fn respond(&mut self, response: Response) {
        let request_id = response.request_id;
        let request = self
            .pending_requests
            .get(&request_id)
            .expect("Request not found");
        let worker = self.require_approved_worker();
        let public_key = worker.public_key.clone();

        let signature: &[u8; 64] = response
            .signature
            .as_slice()
            .try_into()
            .expect("Signature must be 64 bytes");
        let public_key_bytes: &[u8; 32] = public_key
            .as_bytes()
            .try_into()
            .expect("Public key must be 32 bytes");

        // verify response is signed by the worker's public key
        env::ed25519_verify(signature, request.random_seed.as_slice(), public_key_bytes);

        // First get the yield promise of the (potentially timed out) request.
        if let Some(request) = self.pending_requests.remove(&request_id) {
            // Finally, resolve the promise. This will have no effect if the request already timed.
            env::promise_yield_resume(
                &request.yield_index.data_id,
                &serde_json::to_vec(&response.random_number).unwrap(),
            );
        } else {
            env::panic_str("Request not found");
        }
    }

    /// Combine the random seed generated on-chain with the TEE generated random seed
    #[private]
    pub fn on_received_response(
        &mut self,
        _request_id: u64,
        #[callback_result] resp: Result<Vec<u8>, PromiseError>,
    ) -> PromiseOrValue<String> {
        if resp.is_err() {
            env::panic_str("Failed to generate random number");
        }

        PromiseOrValue::Value(encode(resp.unwrap()))
    }
}

impl Contract {
    fn assert_approved_codehash(&self, codehash: &String) {
        require!(
            self.approved_codehashes.contains(codehash),
            "Invalid code hash"
        );
    }

    pub(crate) fn require_approved_worker(&self) -> &Worker {
        let worker = self
            .worker_by_account_id
            .get(&env::predecessor_account_id())
            .expect("Worker not found");
        self.assert_approved_codehash(&worker.codehash);
        worker
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::{testing_env, NearToken};

    fn contract_account_id() -> AccountId {
        accounts(0)
    }

    fn worker_account_id() -> AccountId {
        accounts(1)
    }

    fn requester_account_id() -> AccountId {
        accounts(2)
    }

    fn set_context(signer_account_id: AccountId, attached_deposit: u128) {
        let context = VMContextBuilder::new()
            .current_account_id(contract_account_id())
            .predecessor_account_id(signer_account_id.clone())
            .signer_account_id(signer_account_id)
            .attached_deposit(NearToken::from_yoctonear(attached_deposit))
            .build();
        testing_env!(context);
    }

    fn get_contract() -> Contract {
        Contract::new(contract_account_id())
    }

    #[test]
    fn test_register_worker() {
        let mut contract = get_contract();

        let quote_hex = "0x1234567890".to_string();
        let collateral = "0x1234567890".to_string();
        let checksum = "0x1234567890".to_string();
        let tcb_info = "0x1234567890".to_string();
        let skip_verify = Some(true);

        set_context(worker_account_id(), 1);
        contract.register_worker(quote_hex, collateral, checksum, tcb_info, skip_verify);

        let workers = contract.get_workers(0, 10);
        assert_eq!(workers.len(), 1);

        let worker = contract.get_worker(worker_account_id());
        assert_eq!(worker.unwrap().public_key, env::signer_account_pk());
    }

    #[test]
    fn test_request() {
        let mut contract = get_contract();

        set_context(requester_account_id(), 0);
        contract.request();

        let requests = contract.get_pending_requests(0, 10);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].request_id, 1);
    }
}
