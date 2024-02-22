build:
	cd ../../; \
	dfx canister create --all; \
	dfx build ic_siwe_provider; \
	cd target/wasm32-unknown-unknown/release/; \
	ic-wasm ic_siwe_provider.wasm -o ic_siwe_provider.wasm metadata candid:service -f ../../../packages/ic_siwe_provider/ic_siwe_provider.did -v public; \
	gzip --no-name --force "ic_siwe_provider.wasm"; \
	cp ic_siwe_provider.wasm.gz ../../../packages/ic_siwe_provider/; \

test:
	@{ \
	  make -f ../test_canister/Makefile build; \
		export POCKET_IC_BIN=../../pocket-ic; \
		export IC_SIWE_PROVIDER_PATH=../../target/wasm32-unknown-unknown/release/ic_siwe_provider.wasm.gz; \
		export TEST_CANISTER_PATH=../../target/wasm32-unknown-unknown/release/test_canister.wasm.gz; \
		$(MAKE) build; \
		cargo test --test integration_tests -- --nocapture; \
	}

clean:
	cargo clean