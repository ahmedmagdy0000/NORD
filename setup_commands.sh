#!/bin/bash
# NORD Security System - Command Setup Script
# Developed by DevMonix Technologies (www.devmonix.io)

echo "🛡️ Setting up NORD Security System commands..."

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Create ~/.local/bin if it doesn't exist
mkdir -p "$HOME/.local/bin"

# Create symlinks
echo "📝 Creating command symlinks..."
ln -sf "$SCRIPT_DIR/nord.py" "$HOME/.local/bin/nord"
ln -sf "$SCRIPT_DIR/welcome.py" "$HOME/.local/bin/nord-welcome"

# Make them executable
chmod +x "$HOME/.local/bin/nord"
chmod +x "$HOME/.local/bin/nord-welcome"

# Add to PATH if not already there
if ! echo $PATH | grep -q "$HOME/.local/bin"; then
    echo "🔧 Adding ~/.local/bin to PATH..."
    
    # Add to .bashrc
    if [[ -f "$HOME/.bashrc" ]]; then
        if ! grep -q "$HOME/.local/bin" "$HOME/.bashrc"; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
        fi
    fi
    
    # Add to .zshrc if it exists
    if [[ -f "$HOME/.zshrc" ]]; then
        if ! grep -q "$HOME/.local/bin" "$HOME/.zshrc"; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc"
        fi
    fi
    
    echo "✅ Added ~/.local/bin to PATH in shell configuration"
fi

echo ""
echo "🎉 NORD Security System commands are now set up!"
echo ""
echo "📋 Available commands:"
echo "  nord start          - Start security monitoring"
echo "  nord stop           - Stop security monitoring"
echo "  nord status         - Show system status"
echo "  nord scan           - Run vulnerability scan"
echo "  nord report         - Generate security report"
echo "  nord config         - Show configuration"
echo "  nord-welcome        - Show welcome screen"
echo ""
echo "⚠️  Restart your terminal or run 'source ~/.bashrc' to use commands immediately"
echo ""
echo "🧪 Testing commands..."
export PATH="$HOME/.local/bin:$PATH"

if command -v nord >/dev/null 2>&1; then
    echo "✅ 'nord' command is working!"
    echo "📊 Test: nord --help"
    nord --help
else
    echo "❌ 'nord' command not found. Please restart your terminal."
fi

echo ""
echo "🛡️ NORD Security System is ready to protect your system!"
