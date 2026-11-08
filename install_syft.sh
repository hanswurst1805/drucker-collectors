#!/usr/bin/env bash
# Syft für container_sbom.py installieren (feste Version, Prüfsumme wird kontrolliert).
#   sudo bash install_syft.sh            # nach /opt/drucker-tools (für root-Collector)
#   bash install_syft.sh ~/drucker-tools # ohne root, für rootless Podman
set -euo pipefail

VERSION=1.57.0
DIR="${1:-/opt/drucker-tools}"
case "$(uname -m)" in
    x86_64)  ARCH=amd64 ;;
    aarch64) ARCH=arm64 ;;
    *) echo "FEHLER: Architektur $(uname -m) nicht unterstützt"; exit 1 ;;
esac
FILE="syft_${VERSION}_linux_${ARCH}.tar.gz"
BASE="https://github.com/anchore/syft/releases/download/v${VERSION}"

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/$FILE" "$BASE/$FILE"
curl -fsSL -o "$TMP/sums" "$BASE/syft_${VERSION}_checksums.txt"
(cd "$TMP" && grep " $FILE\$" sums | sha256sum -c -)
tar xzf "$TMP/$FILE" -C "$TMP" syft
mkdir -p "$DIR"
install -m 755 "$TMP/syft" "$DIR/syft"
"$DIR/syft" version | grep -E "^Version"
