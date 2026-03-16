#!/usr/bin/env bash
set -euo pipefail

# Build a .deb package from a pre-built TorchSight binary.
#
# Usage:
#   ./build-deb.sh <binary-path> [version]
#
# Example:
#   ./build-deb.sh ./torchsight-linux-x86_64 1.0.0

BINARY="${1:?Usage: build-deb.sh <binary-path> [version]}"
VERSION="${2:-1.0.0}"
PKG="torchsight"
ARCH="amd64"
WORKDIR="$(mktemp -d)"
PKG_DIR="${WORKDIR}/${PKG}_${VERSION}_${ARCH}"

trap 'rm -rf "${WORKDIR}"' EXIT

echo "Building ${PKG}_${VERSION}_${ARCH}.deb ..."

# Directory structure
mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/usr/local/bin"

# Install binary
cp "${BINARY}" "${PKG_DIR}/usr/local/bin/torchsight"
chmod 755 "${PKG_DIR}/usr/local/bin/torchsight"

# Control file
cat > "${PKG_DIR}/DEBIAN/control" <<EOF
Package: ${PKG}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: TorchSight <packages@torchsight.io>
Depends: tesseract-ocr, poppler-utils
Recommends: ollama
Description: Open-source security scanner and document classifier powered by local LLMs
 TorchSight scans text, image, and PDF files for sensitive data, credentials,
 malicious payloads, and classified content using on-premise LLMs via Ollama.
Homepage: https://github.com/IvanDobrovolsky/torchsight
License: Apache-2.0
EOF

# Post-install: remind user to set up Ollama model
cat > "${PKG_DIR}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
echo ""
echo "TorchSight installed successfully."
echo ""
echo "To complete setup, ensure Ollama is running and pull the model:"
echo "  ollama pull torchsight/beam"
echo ""
EOF
chmod 755 "${PKG_DIR}/DEBIAN/postinst"

# Build the package
dpkg-deb --build "${PKG_DIR}"

# Move to current directory
mv "${WORKDIR}/${PKG}_${VERSION}_${ARCH}.deb" .

echo "Created: ${PKG}_${VERSION}_${ARCH}.deb"
