build:
	cd ../../; \
	dfx canister create --all; \
	dfx build ic_siwe_provider; \
	gzip --no-name --force "target/wasm32-unknown-unknown/release/ic_siwe_provider.wasm"; \
	cp target/wasm32-unknown-unknown/release/ic_siwe_provider.wasm.gz packages/ic_siwe_provider/; \

test:
	@{ \
		export POCKET_IC_BIN=../../pocket-ic; \
		export IC_SIWE_PROVIDER_PATH=../../target/wasm32-unknown-unknown/release/ic_siwe_provider.wasm.gz; \
		export TEST_CANISTER_PATH=../../target/wasm32-unknown-unknown/release/test_canister.wasm.gz; \
		$(MAKE) build; \
		cargo test --test integration_tests -- --nocapture; \
	}

clean:
	cargo clean