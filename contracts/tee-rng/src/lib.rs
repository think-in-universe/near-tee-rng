use dcap_qvl::{verify, QuoteCollateralV3};
use hex::{decode, encode};
use near_sdk::{
    assert_one_yocto,
    env::{self, block_timestamp},
    ext_contract,
    json_types::U128,
    log, near, require,
    store::{IterableMap, IterableSet, Vector},
    AccountId, BorshStorageKey, Gas, NearToken, PanicOnDefault, Promise, PromiseError, PublicKey,
};

use crate::events::*;

mod admin;
mod collateral;
mod events;
mod upgrade;
mod view;

#[near]
#[derive(BorshStorageKey)]
pub enum Prefix {
    ApprovedCodeHashes,
    WorkerByAccountId,
}

#[near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct Worker {
    checksum: String,
    codehash: String,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    owner_id: AccountId,
    approved_codehashes: IterableSet<String>,
    worker_by_account_id: IterableMap<AccountId, Worker>,
}

#[allow(dead_code)]
#[ext_contract(ext_intents_vault)]
trait IntentsVaultContract {
    fn add_public_key(intents_contract_id: AccountId, public_key: PublicKey);

    fn ft_withdraw(
        intents_contract_id: AccountId,
        token: AccountId,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: Option<String>,
    );
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
        }
    }

    #[payable]
    pub fn register_worker(
        &mut self,
        quote_hex: String,
        collateral: String,
        checksum: String,
        tcb_info: String,
    ) -> Promise {
        assert_one_yocto();

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

        let worker_id = env::predecessor_account_id();

        self.worker_by_account_id.insert(
            worker_id.clone(),
            Worker {
                checksum: checksum.clone(),
                codehash: codehash.clone(),
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
