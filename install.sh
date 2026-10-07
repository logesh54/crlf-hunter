#!/bin/bash
# crlf-hunter installer
# Creates a symlink to make crlf-hunter available as a command

set -e

INSTALL_DIR="/usr/local/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_SCRIPT="$SCRIPT_DIR/crlf_hunter/cli.py"
LINK_NAME="crlf-hunter"
LINK_PATH="$INSTALL_DIR/$LINK_NAME"

echo "Installing crlf-hunter..."
echo "Script location: $CLI_SCRIPT"
echo "Install location: $LINK_PATH"

# Check if CLI script exists
if [ ! -f "$CLI_SCRIPT" ]; then
    echo "Error: CLI script not found at $CLI_SCRIPT"
    exit 1
fi

# Make CLI script executable
chmod +x "$CLI_SCRIPT"

# Create symlink (requires sudo for /usr/local/bin)
if [ "$EUID" -ne 0 ]; then
    echo "This installer needs root privileges to create symlink in $INSTALL_DIR"
    echo "Re-running with sudo..."
    exec sudo "$0" "$@"
fi

# Remove existing symlink if present
if [ -L "$LINK_PATH" ] || [ -f "$LINK_PATH" ]; then
    echo "Removing existing installation..."
    rm -f "$LINK_PATH"
fi

# Create new symlink
ln -s "$CLI_SCRIPT" "$LINK_PATH"
echo "Created symlink: $LINK_PATH -> $CLI_SCRIPT"

# Verify installation
if command -v crlf-hunter >/dev/null 2>&1; then
    echo ""
    echo "Installation successful!"
    echo "Run 'crlf-hunter --help' to get started."
else
    echo ""
    echo "Warning: crlf-hunter command not found in PATH."
    echo "You may need to restart your shell or add $INSTALL_DIR to your PATH."
fi