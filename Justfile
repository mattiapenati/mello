@_default:
	just -l

# build crate documentation
doc:
	RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --all-features -p mello --no-deps
