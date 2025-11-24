#!/bin/bash
# NORD Security System Installation Script for Parrot OS
# Developed by DevMonix Technologies (www.devmonix.io)

set -e

echo "=== NORD Security System Installation Script ==="
echo "Installing enterprise-grade security tool for Parrot OS..."

# Check if running as root for system-wide installation
if [[ $EUID -eq 0 ]]; then
    INSTALL_DIR="/opt/nord_security"
    BIN_DIR="/usr/local/bin"
    echo "Installing system-wide..."
else
    INSTALL_DIR="$HOME/.local/nord_security"
    BIN_DIR="$HOME/.local/bin"
    echo "Installing for current user..."
fi

# Create directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$BIN_DIR"
mkdir -p "$HOME/.nord_security/logs"

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt --user

# Copy files
echo "Installing NORD Security System files..."
cp nord.py "$INSTALL_DIR/"
cp welcome.py "$INSTALL_DIR/"
cp nord_gui.py "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/nord.py"
chmod +x "$INSTALL_DIR/welcome.py"

# Create symlinks in PATH
echo "Creating NORD Security command symlinks..."
ln -sf "$INSTALL_DIR/nord.py" "$BIN_DIR/nord"
ln -sf "$INSTALL_DIR/welcome.py" "$BIN_DIR/nord-welcome"

# Make scripts executable
chmod +x "$BIN_DIR/nord"
chmod +x "$BIN_DIR/nord-welcome"

# Add ~/.local/bin to PATH if not already present
if [[ "$BIN_DIR" == "$HOME/.local/bin" ]]; then
    if ! echo $PATH | grep -q "$HOME/.local/bin"; then
        echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$HOME/.bashrc"
        echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$HOME/.zshrc" 2>/dev/null || true
        echo "📝 Added ~/.local/bin to PATH in shell configuration"
    fi
fi

# Create desktop entry
if [[ $EUID -eq 0 ]]; then
    cat > /usr/share/applications/nord.desktop << EOF
[Desktop Entry]
Name=NORD Security System
Comment=Defensive Security Tool for Parrot OS
Exec=nord status
Icon=security-high
Terminal=true
Type=Application
Categories=Security;System;
EOF
else
    mkdir -p "$HOME/.local/share/applications"
    cat > "$HOME/.local/share/applications/nord.desktop" << EOF
[Desktop Entry]
Name=NORD Security System
Comment=Defensive Security Tool for Parrot OS
Exec=nord status
Icon=security-high
Terminal=true
Type=Application
Categories=Security;System;
EOF
fi

# Create systemd service (system-wide only)
if [[ $EUID -eq 0 ]]; then
    cat > /etc/systemd/system/nord.service << EOF
[Unit]
Description=NORD Security Monitor
After=network.target

[Service]
Type=simple
User=root
ExecStart=$INSTALL_DIR/nord.py start
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo "Systemd service created. Enable with: systemctl enable --now nord"
fi

# Add to PATH if not already there
if ! echo $PATH | grep -q "$BIN_DIR"; then
    echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$HOME/.bashrc"
    echo "Added $BIN_DIR to PATH. Restart terminal or run: source ~/.bashrc"
fi

echo ""
echo "=== Installation Complete ==="
echo "NORD Security System has been installed successfully!"
echo ""
echo "Usage:"
echo "  nord start               - Start monitoring"
echo "  nord status              - Show status"
echo "  nord scan                - Run vulnerability scan"
echo "  nord report              - Generate security report"
echo "  nord config              - Show configuration location"
echo "  nord-welcome             - Show welcome screen"
echo "  nord_gui.py              - Launch GUI interface"
echo ""
echo "Configuration directory: $HOME/.nord_security"
echo "Logs directory: $HOME/.nord_security/logs"
echo ""
echo "⚠️  NOTE: You may need to restart your terminal or run 'source ~/.bashrc' to use the 'nord' command directly."
