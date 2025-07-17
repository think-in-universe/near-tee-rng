use near_gas::NearGas;
use near_sdk::NearToken;
use serde_json::json;

mod constants;
mod utils;

use constants::*;
use utils::*;

#[ignore = "The remote attestation report data cannot be equal to the public key"]
#[tokio::test]
async fn test_register_worker() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting test...");
    let sandbox = near_workspaces::sandbox().await?;

    let owner = create_account(&sandbox, "owner", 10).await?;

    println!("Deploying TEE RNG contract...");
    let tee_rng = deploy_tee_rng(&sandbox, &owner).await?;

    // Approve codehash by owner
    let result = owner
        .call(tee_rng.id(), "approve_codehash")
        .args_json(json!({
            "codehash": CODE_HASH
        }))
        .transact()
        .await?;
    assert!(
        result.is_success(),
        "{:#?}",
        result.into_result().unwrap_err()
    );

    // Register worker (TODO: verify public key)
    let collateral = include_str!("samples/quote_collateral.json").to_string();
    let result = tee_rng
        .call("register_worker")
        .args_json(json!({
            "quote_hex": QUOTE_HEX.to_string(),
            "collateral": collateral,
            "checksum": CHECKSUM.to_string(),
            "tcb_info": TCB_INFO.to_string()
        }))
        .deposit(NearToken::from_yoctonear(1))
        .gas(NearGas::from_tgas(300))
        .transact()
        .await?;
    assert!(
        result.is_success(),
        "{:#?}",
        result.into_result().unwrap_err()
    );

    let result_get_worker = tee_rng
        .view("get_worker")
        .args_json(json!({"account_id" : tee_rng.id()}))
        .await?;

    let worker: WorkerInfo = serde_json::from_slice(&result_get_worker.result).unwrap();
    println!(
        "\n [LOG] Worker: {{ checksum: {}, codehash: {} }}",
        worker.checksum, worker.codehash
    );

    Ok(())
}
