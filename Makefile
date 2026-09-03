intelmac:
	RUSTFLAGS='-C target-cpu=haswell' cargo build --release --target x86_64-apple-darwin

intelwin:
	RUSTFLAGS='-C target-cpu=haswell' cargo xwin build --release --target x86_64-pc-windows-msvc
