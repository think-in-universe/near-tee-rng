# NEAR TEE RNG

Random Number Generator (RNG) system for NEAR Protocol, combining a smart contract and a Trusted Execution Environment (TEE) worker for secure, verifiable, and unbiased randomness.

## Overview

- **[RNG Smart Contract](./contracts/tee-rng)**: Allows users to request random numbers on-chain. Integrates with a TEE worker to provide cryptographically secure and verifiable randomness. [Learn more in the contract's README.](contracts/tee-rng/README.md)
- **[TEE Worker](./worker/)**: Listens for randomness requests from the contract, generates random numbers inside a TEE, with cryptographic proof and attestation.

## How It Works

1. **User Request**: A user calls the `request` function on the smart contract, which generates a random seed and triggers a `yield`.
2. **TEE Worker Response**: The TEE worker detects the request, generates a random number using TEE-derived secrets, and calls the `respond` function to deliver the result and signature back to the contract. User's request will be resumed and returned, after contract received this response from worker.
