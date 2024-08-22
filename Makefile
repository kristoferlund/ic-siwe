doc:
	cargo doc --no-deps --document-private-items
	cp -r packages/ic_siwe/media target/doc/ic_siwe/media
	
clean:
	rm -rf .dfx
	rm -f .env
	rm -rf target
	rm -rf node_modules
	cargo clean
