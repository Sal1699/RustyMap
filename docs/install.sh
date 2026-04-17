#!/usr/bin/env bash
# RustyMap installer (Linux / macOS)
# Usage:
#   curl -fsSL https://sal1699.github.io/RustyMap/install.sh | bash
#   curl -fsSL https://sal1699.github.io/RustyMap/install.sh | bash -s -- --prefix=$HOME/.local/bin
#   curl -fsSL https://sal1699.github.io/RustyMap/install.sh | bash -s -- --version=v0.1.0

set -euo pipefail

REPO="Sal1699/RustyMap"
VERSION="latest"
PREFIX=""

# ── args ─────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --prefix=*)  PREFIX="${arg#*=}" ;;
    --version=*) VERSION="${arg#*=}" ;;
    -h|--help)
      cat <<EOF
RustyMap installer

Options:
  --prefix=<dir>    install directory (default: /usr/local/bin if writable, else \$HOME/.local/bin)
  --version=<tag>   release tag to install (default: latest)
  -h, --help        show this help
EOF
      exit 0
      ;;
    *)
      echo "unknown arg: $arg" >&2
      exit 2
      ;;
  esac
done

# ── colors ───────────────────────────────────────────
if [ -t 1 ]; then
  O=$'\033[38;2;247;129;0m'; A=$'\033[38;2;255;176;0m'; Y=$'\033[38;2;245;232;46m'
  D=$'\033[38;2;140;90;20m'; R=$'\033[0m'
else
  O=""; A=""; Y=""; D=""; R=""
fi

say()  { printf "%sλ%s %s\n" "$O" "$R" "$1"; }
warn() { printf "%s!%s %s\n" "$Y" "$R" "$1" >&2; }
die()  { printf "%sx%s %s\n" "$A" "$R" "$1" >&2; exit 1; }

# ── detect os/arch ───────────────────────────────────
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  linux)  OS_TAG="linux" ;;
  darwin) OS_TAG="macos" ;;
  *) die "OS non supportato: $OS. Compila da sorgente: https://github.com/$REPO" ;;
esac

case "$ARCH" in
  x86_64|amd64) ARCH_TAG="x86_64" ;;
  arm64|aarch64)
    if [ "$OS_TAG" = "linux" ]; then
      die "Linux aarch64 non è nei binari pre-compilati. Compila da sorgente: https://github.com/$REPO"
    fi
    ARCH_TAG="aarch64"
    ;;
  *) die "Architettura non supportata: $ARCH" ;;
esac

ASSET="rustymap-${OS_TAG}-${ARCH_TAG}.tar.gz"

# ── pick prefix ──────────────────────────────────────
if [ -z "$PREFIX" ]; then
  if [ -w "/usr/local/bin" ] 2>/dev/null; then
    PREFIX="/usr/local/bin"
  else
    PREFIX="$HOME/.local/bin"
  fi
fi

mkdir -p "$PREFIX"

# ── download ─────────────────────────────────────────
if [ "$VERSION" = "latest" ]; then
  URL="https://github.com/$REPO/releases/latest/download/$ASSET"
else
  URL="https://github.com/$REPO/releases/download/$VERSION/$ASSET"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say "detected: ${A}${OS_TAG}/${ARCH_TAG}${R} · version: ${A}${VERSION}${R}"
say "download: ${D}${URL}${R}"

if command -v curl >/dev/null 2>&1; then
  curl -fsSL --retry 3 -o "$TMP/$ASSET" "$URL" || die "download fallito"
elif command -v wget >/dev/null 2>&1; then
  wget -q -O "$TMP/$ASSET" "$URL" || die "download fallito"
else
  die "serve curl o wget"
fi

say "estrazione..."
tar -xzf "$TMP/$ASSET" -C "$TMP"

BIN="$(find "$TMP" -type f -name 'rustymap' -not -path '*.d*' | head -n1)"
[ -n "$BIN" ] || die "binario rustymap non trovato nell'archivio"

# ── install ──────────────────────────────────────────
DEST="$PREFIX/rustymap"

if [ -w "$PREFIX" ]; then
  install -m 0755 "$BIN" "$DEST"
else
  warn "scrittura in $PREFIX richiede sudo"
  sudo install -m 0755 "$BIN" "$DEST"
fi

say "installato in ${A}${DEST}${R}"

# ── libpcap check ────────────────────────────────────
if [ "$OS_TAG" = "linux" ]; then
  if ! ldconfig -p 2>/dev/null | grep -q libpcap; then
    warn "libpcap non rilevata. Installa:"
    warn "  Debian/Ubuntu: sudo apt install libpcap0.8"
    warn "  Fedora/RHEL:   sudo dnf install libpcap"
    warn "  Arch:          sudo pacman -S libpcap"
  fi
fi

# ── PATH hint ────────────────────────────────────────
case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *)
    warn "$PREFIX non è in PATH. Aggiungi al tuo shell rc:"
    warn "  export PATH=\"$PREFIX:\$PATH\""
    ;;
esac

printf "\n%sλ%s Rise and shine, Mr. Freeman...\n" "$O" "$R"
printf "  %srustymap --guide%s\n\n" "$Y" "$R"
