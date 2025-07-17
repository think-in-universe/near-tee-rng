use near_contract_standards::fungible_token::{metadata::FungibleTokenMetadata, Balance};
use near_gas::NearGas;
use near_sdk::{json_types::U128, near, AccountId, NearToken};
use near_workspaces::{network::Sandbox, result::ExecutionFinalResult, Account, Contract, Worker};
use serde_json::json;

pub const TEE_RNG_CONTRACT_WASM: &str = "../../target/near/tee_rng/tee_rng.wasm";

#[near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct WorkerInfo {
    pub checksum: String,
    pub codehash: String,
}

pub async fn create_account(
    sandbox: &Worker<Sandbox>,
    prefix: &str,
    balance: Balance,
) -> Result<Account, Box<dyn std::error::Error>> {
    let root = sandbox.root_account().unwrap();
    Ok(root
        .create_subaccount(prefix)
        .initial_balance(NearToken::from_near(balance))
        .transact()
        .await?
        .result)
}

pub async fn deploy_tee_rng(
    sandbox: &Worker<Sandbox>,
    owner: &Account,
) -> Result<Contract, Box<dyn std::error::Error>> {
    let tee_rng_contract_wasm =
        std::fs::read(TEE_RNG_CONTRACT_WASM).expect("Contract wasm not found");
    let tee_rng_account = create_account(sandbox, "tee-rng", 100).await?;
    let tee_rng_contract = tee_rng_account
        .deploy(&tee_rng_contract_wasm)
        .await?
        .result;

    println!("Initializing TEE RNG contract...");
    let result = tee_rng_contract
        .call("new")
        .args_json(json!({
            "owner_id": owner.id(),
        }))
        .transact()
        .await?;
    println!("\nResult init: {:?}", result);

    Ok(tee_rng_contract)
}
