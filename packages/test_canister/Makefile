build:
	cd ../../; \
	dfx canister create --all; \
	dfx build test_canister; \
	gzip --no-name --force "target/wasm32-unknown-unknown/release/test_canister.wasm"; \

