#!/bin/bash
set -e

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║     scala-dep-scan  •  macOS installer                  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check for Rust / cargo
if ! command -v cargo &> /dev/null; then
    echo "► Rust not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    echo "✓ Rust installed"
else
    echo "✓ Rust found: $(rustc --version)"
fi

echo ""
echo "► Compiling scala-dep-scan (this takes ~1-2 min first time)..."
cd "$DIR"
cargo build --release

BINARY="$DIR/target/release/scala-dep-scan"
echo ""
echo "✓ Build complete: $BINARY"
echo ""

# Try to install to a common location
INSTALL_DIRS=("/usr/local/bin" "$HOME/.local/bin" "$HOME/bin")
INSTALLED=false

for DIR_PATH in "${INSTALL_DIRS[@]}"; do
    if [ -d "$DIR_PATH" ] && [ -w "$DIR_PATH" ]; then
        cp "$BINARY" "$DIR_PATH/scala-dep-scan"
        echo "✓ Installed to $DIR_PATH/scala-dep-scan"
        INSTALLED=true
        break
    fi
done

if [ "$INSTALLED" = false ]; then
    echo "► Could not find writable install dir. Run directly with:"
    echo "   $BINARY /path/to/your/scala/project"
    echo ""
    echo "  Or copy manually:"
    echo "   sudo cp $BINARY /usr/local/bin/scala-dep-scan"
fi

echo ""
echo "Usage:"
echo "  scala-dep-scan /path/to/your/scala/project"
echo "  scala-dep-scan . --osv --dot deps.dot"
echo "  scala-dep-scan . -f json | jq '.summary'"
echo ""
