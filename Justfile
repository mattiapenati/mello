@_default:
	just -l

# build wasm code
wasm-pack:
	wasm-pack build --out-dir ../wasm --target deno --release
	rm -f wasm/.gitignore wasm/LICENSE-MIT wasm/LICENSE-APACHE
