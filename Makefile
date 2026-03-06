.PHONY: build release install test clean

build:
	cargo build

release:
	cargo build --release

install: release
	mkdir -p $(HOME)/.local/bin
	cp target/release/torchsight $(HOME)/.local/bin/torchsight
	@echo "Installed to $(HOME)/.local/bin/torchsight"

test:
	cargo test

clean:
	cargo clean

setup:
	@bash install.sh

uninstall:
	rm -f $(HOME)/.local/bin/torchsight
	@echo "Removed torchsight from $(HOME)/.local/bin"
