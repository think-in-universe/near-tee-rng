RUSTFLAGS = "-C link-arg=-s"

all: lint tee-rng

lint:
	@cargo fmt --all
	@cargo clippy --fix --allow-dirty --allow-staged

tee-rng:
	$(call compile-release,tee-rng)
	@mkdir -p contracts/tee-rng/res
	@cp target/near/tee_rng/tee_rng.wasm ./contracts/tee-rng/res/tee_rng.wasm

test: tee-rng
	cargo test -- --nocapture

define compile-release
	@rustup target add wasm32-unknown-unknown
	@cd contracts/$(1) && cargo near build non-reproducible-wasm $(if $(2),--features $(2))
endef
