# Agent Guide

This repository provides Sign‑In with Ethereum (SIWE) for the Internet Computer (ICP).
It includes a reusable Rust library and a prebuilt provider canister, plus demos and a JS helper.

## What’s Here
- `packages/ic_siwe` — Core Rust library for SIWE in ICP canisters.
- `packages/ic_siwe_provider` — Prebuilt identity provider canister (Candid `.did`, prebuilt `.wasm.gz`, integration tests).
- `packages/test_canister` — Utility canister used by integration tests.
- `packages/ic_siwe_js` — JS/TS helpers (React/Vue bindings).
- Docs and media: top‑level `README.md`, per‑package READMEs, `media/`.

Workspace is managed by Cargo and DFX.

## Prerequisites
- Rust stable; add the Wasm target: `rustup target add wasm32-unknown-unknown`.
- DFX >= 0.15.
- For provider build: `gzip`; optional `ic-wasm` (used to embed Candid metadata; tests run without it).
- `ic-wasm` can be installed using `cargo install ic-wasm`.
- Node 18+ and `pnpm` if touching the JS package.

## Quickstart: Build and Test
- Generate docs: `make doc` (outputs under `target/doc/`).
- Clean workspace: `make clean`.

Library (ic_siwe)
- Run tests: `make -C packages/ic_siwe test`
  - Alternative: `cargo test -p ic_siwe`

Provider Canister (ic_siwe_provider)
- Build canister artifacts: `make -C packages/ic_siwe_provider build`
- Run integration tests (PocketIC): `make -C packages/ic_siwe_provider test`
  - Note: This target builds helper canisters and runs tests. If `ic-wasm` is missing you may see a warning; tests still run.

JS/TS helpers (optional)
- Build and lint: `cd packages/ic_siwe_js && pnpm i && pnpm build && pnpm lint`

## Coding Conventions
- Rust: use `rustfmt` and prefer `cargo fmt` before submitting changes. Types `PascalCase`; modules/functions `snake_case`; 4‑space indent. Lint with `cargo clippy -p <crate>`.
- TypeScript: 2‑space indent; ESLint configured in `packages/ic_siwe_js/eslint.config.js`. Prefer kebab‑case filenames.
- Candid: keep `packages/ic_siwe_provider/ic_siwe_provider.did` authoritative; provider build embeds metadata into the Wasm.

## Testing Notes
- Unit tests live next to Rust modules via `#[test]`.
- Provider integration tests live in `packages/ic_siwe_provider/tests/*.rs` and run on PocketIC.
- Cover: SIWE message prep/parse, address validation, hashing, login/delegation, guards (authenticated calls), and upgrade paths.

## PR & Release Hygiene
- Commits: short, imperative subjects; include scope when helpful (e.g., `provider: guard siwe_login`).
- PRs: include summary, motivation, linked issues, and note any breaking changes. If Candid or public API changed, add before/after examples and update the prebuilt Wasm (`make -C packages/ic_siwe_provider build`).
- When bumping versions: update the crate `Cargo.toml`, package `CHANGELOG.md`, and any README references (e.g., release URLs in provider README).

## Security Tips
- Never commit secrets. DFX‑generated `.env` is ignored.
- Be cautious in crypto‑sensitive code paths (signature recovery, message hashing, delegation). Keep changes minimal and add tests.
