armmac:
	RUSTFLAGS='-C target-cpu=native' cargo build --release --target aarch64-apple-darwin

intelmac:
	RUSTFLAGS='-C target-cpu=haswell' cargo build --release --target x86_64-apple-darwin

intelwin:
	RUSTFLAGS='-C target-cpu=haswell' cargo xwin build --release --target x86_64-pc-windows-msvc
