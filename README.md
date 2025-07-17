# tee-rng
Random Number Generator contract powered by TEE

## RNG Contract

1. User can request a random number with a `request` function that generate a random seed first. It triggers a `yield` that will be listened by the RNG Worker inside TEE, and resumed after the worker calls `respond` function. 

## RNG Worker

1. Listens to requests from RNG contract, and creates a random number from TEE derived private key and call `respond` function that returns the hashed random number to user
