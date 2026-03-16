.PHONY: build release install test clean setup uninstall

build:
	cargo build

release:
	cargo build --release

install: release
	mkdir -p $(HOME)/.local/bin
	cp target/release/torchsight $(HOME)/.local/bin/torchsight
	@echo "Installed to $(HOME)/.local/bin/torchsight"
	@if ! echo "$$PATH" | grep -q "$(HOME)/.local/bin"; then \
		RCFILE=""; \
		case "$$(basename $$SHELL)" in \
			zsh)  RCFILE="$(HOME)/.zshrc" ;; \
			bash) RCFILE="$(HOME)/.bashrc" ;; \
			*)    RCFILE="$(HOME)/.profile" ;; \
		esac; \
		if ! grep -q '.local/bin' "$$RCFILE" 2>/dev/null; then \
			echo '' >> "$$RCFILE"; \
			echo '# TorchSight' >> "$$RCFILE"; \
			echo 'export PATH="$$HOME/.local/bin:$$PATH"' >> "$$RCFILE"; \
			echo "Added ~/.local/bin to PATH in $$RCFILE"; \
			echo "Run: source $$RCFILE"; \
		fi \
	fi

test:
	cargo test

clean:
	cargo clean

setup:
	@bash install.sh

uninstall:
	rm -f $(HOME)/.local/bin/torchsight
	@echo "Removed torchsight from $(HOME)/.local/bin"
