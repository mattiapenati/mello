# mello

![Apache 2.0 OR MIT licensed](https://img.shields.io/badge/license-Apache2.0%2FMIT-blue.svg)

`mello` is a collection of reusable pieces of code that I write to speedup the
deveolpment of my code. It contains solutions for a broad class of problems of
backend development:

- cryptographic key derivation solution that uses
  [argon2](https://crates.io/crates/argon2);
- signed ticket to manage user invitation or password change based on Ed22519 (a
  thin wrapper of [ed25519_dalek](https://crates.io/crates/ed25519-dalek));
- middleware for CSRF protection (backend in Rust and frontend in WASM);
- reverse proxy (without load balacing and minimal configuration);
- a key-value storage based on SQLite;
- date-time mocking (a wrapper of [time](https://crates.io/crates/time)).

Some of these solutions are already available in crates that are probably
written better than `mello`, but I need to write the code to learn something new
and sometime the already available solutions does not fit my personal code
ergonomics.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
