all:
	cargo test

debug:
	cargo test -- --nocapture

clean:
	cargo clean
