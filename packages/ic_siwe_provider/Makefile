.PHONY: build test

build:
	cd ../../; \
	dfx build; \
	gzip --no-name --force "target/wasm32-unknown-unknown/release/ic_siwe_provider.wasm"; \

test:
	@{ \
		export POCKET_IC_BIN=../../pocket-ic; \
		export WASM_PATH=../../target/wasm32-unknown-unknown/release/ic_siwe_provider.wasm.gz; \
		make build; \
		cargo test -- --nocapture; \
	}
