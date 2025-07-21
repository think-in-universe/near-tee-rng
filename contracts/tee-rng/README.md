# TEE-based RNG Smart Contract

A secure, verifiable, and unbiased Random Number Generator (RNG) smart contract for NEAR Protocol, powered by Trusted Execution Environment (TEE) technology. This contract enables users to request random numbers that are generated inside a TEE, ensuring cryptographic security, transparency, and resistance to manipulation. The contract leverages TEE attestation to prove the integrity of the randomness generation process, providing strong guarantees for on-chain applications such as gaming, lotteries, and cryptographic protocols.

## Features

- **Secure Randomness Generation**
  - Random numbers are generated via both NEAR Protocol built-in host function and Trusted Execution Environment (TEE), ensuring cryptographic security and resistance to tampering.
- **Verifiable and Unbiased**
  - Each random number is accompanied by cryptographic proof and TEE attestation, allowing anyone to verify its authenticity and fairness.
- **On-Chain Randomness Requests**
  - Users can request random numbers directly from the smart contract, with results delivered in the same function call via `yield/resume` mechanism on NEAR Protocol.
- **Transparency and Auditability**
  - All randomness requests and responses are recorded on-chain, providing a transparent and auditable history.
- **Suitable for Critical Applications**
  - Designed for use in gaming, lotteries, cryptographic protocols, and any application requiring strong guarantees of randomness integrity.

## Smart Contract Methods

### Worker Registration

#### `register_worker`
```rust
#[payable]
pub fn register_worker(
    quote_hex: String,
    collateral: String,
    checksum: String,
    tcb_info: String,
)
```
Registers a new worker agent after verifying TEE attestation. Only workers with an approved codehash can register. Requires a 1 yoctoNEAR deposit.

### Randomness Methods

#### `request`
```rust
#[payable]
pub fn request()
```

Requests a random number from the contract. Requires a minimum deposit of 0.005 NEAR to avoid potential storage attack. 

#### `respond`
```rust
pub fn respond(response: Response)
```
Called by a registered worker to respond to a randomness request. Verifies the worker's signature and public key, and resumes the promise for the requester.


## Build

Install [`cargo-near`](https://github.com/near/cargo-near) and run:

```bash
make all
```

## Test

```bash
make test
```

## Deployment

```bash
cargo near deploy <account-id>
```

## Security Considerations

- All sensitive methods are protected by worker verification and codehash approval
- Worker registration requires valid TEE attestation and collateral
- Random number generation access control is managed through codehash verification
- Owner-only administrative and upgrade functions
- All critical actions are logged and important events are emitted

## Technical Architecture

1. **Worker Registration Flow**
   - TEE generates attestation quote
   - Contract verifies quote authenticity and collateral
   - Worker codehash and checksum are stored if codehash is approved
   - Emits a registration event
   
2. **Randomness Request Flow**
   - User requests randomness with deposit
   - Worker responds with signed random number
   - Contract verifies signature and resumes promise
   - Result is returned to the requester

3. **Method Access Control**
   - Only workers with approved codehashes can access protected functions
   - Owner manages approved codehash list

## Useful Links

- [NEAR Rust SDK Documentation](https://docs.near.org/smart-contracts/quickstart)
- [Chain Abstraction Telegram Group](https://t.me/chain_abstraction)
- [Shade Agent Reference](https://near.ai/shade)
