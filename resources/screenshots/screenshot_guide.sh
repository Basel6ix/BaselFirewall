#!/bin/bash

echo "BaselFirewall Screenshot Guide"
echo "============================="
echo
echo "This script provides commands and instructions for taking screenshots."
echo

# Check for screenshot tools
if ! command -v gnome-screenshot &> /dev/null; then
    echo "Installing GNOME Screenshot tool..."
    sudo apt-get install gnome-screenshot -y
fi

if ! command -v flameshot &> /dev/null; then
    echo "Installing Flameshot (recommended)..."
    sudo apt-get install flameshot -y
fi

echo "Available Screenshot Methods:"
echo "---------------------------"
echo
echo "1. Flameshot (Recommended)"
echo "   - Interactive screenshot with annotation tools"
echo "   Command: flameshot gui"
echo "   Hotkey: PrtScr (after configuration)"
echo
echo "2. GNOME Screenshot"
echo "   - Full screen: gnome-screenshot"
echo "   - Selected area: gnome-screenshot -a"
echo "   - Window with delay: gnome-screenshot -w -d 5"
echo
echo "3. ImageMagick (for automation)"
echo "   - Full screen: import -window root screenshot.png"
echo "   - Selected window: import screenshot.png"
echo
echo "Quick Commands for BaselFirewall Screenshots:"
echo "------------------------------------------"
echo

# Function to create screenshot commands for a section
create_section_commands() {
    local section=$1
    local description=$2
    echo "# $description"
    echo "mkdir -p /home/basel6ix/BaselFirewall/resources/screenshots/$section"
    echo "cd /home/basel6ix/BaselFirewall/resources/screenshots/$section"
    echo "flameshot gui -p /home/basel6ix/BaselFirewall/resources/screenshots/$section"
    echo "# or"
    echo "gnome-screenshot -a -f ${section}_screenshot.png"
    echo
}

# Generate commands for each section
create_section_commands "initial_setup" "Installation and Setup Screenshots"
create_section_commands "gui_demo" "GUI Interface Screenshots"
create_section_commands "ids_ips" "IDS/IPS Feature Screenshots"
create_section_commands "dos_protection" "DoS Protection Screenshots"
create_section_commands "user_management" "User Management Screenshots"
create_section_commands "security_features" "Security Features Screenshots"
create_section_commands "performance" "Performance Metrics Screenshots"
create_section_commands "logging" "Logging System Screenshots"
create_section_commands "backup" "Backup System Screenshots"

echo "Tips for Taking Good Screenshots:"
echo "------------------------------"
echo "1. Use Flameshot for interactive screenshots with annotations"
echo "2. Set a delay (3-5 seconds) when capturing menus or dropdowns"
echo "3. Ensure the window is properly sized (1920x1080 minimum)"
echo "4. Use the naming convention: section_name_description.png"
echo "5. Capture any relevant tooltips or hover states"
echo "6. Include success/error messages when relevant"
echo
echo "Recommended Workflow:"
echo "------------------"
echo "1. Start the BaselFirewall application"
echo "2. Open this script in a terminal"
echo "3. Follow the demo script section by section"
echo "4. Use Flameshot for interactive screenshots (flameshot gui)"
echo "5. Save screenshots with descriptive names in the correct directory"
echo "6. Review screenshots for clarity and completeness"
echo
echo "To configure Flameshot as the default screenshot tool:"
echo "------------------------------------------------"
echo "1. Open Settings > Keyboard > Shortcuts"
echo "2. Find 'Screenshots' section"
echo "3. Set 'flameshot gui' as the command for PrtScr"
echo
echo "To start taking screenshots:"
echo "------------------------"
echo "1. Make sure BaselFirewall is running"
echo "2. Choose your preferred screenshot method"
echo "3. Use the commands above for each section"
echo "4. Save files with descriptive names"
echo
echo "For automation (requires ImageMagick):"
echo "---------------------------------"
echo "for section in initial_setup gui_demo ids_ips dos_protection user_management security_features performance logging backup; do"
echo "    mkdir -p /home/basel6ix/BaselFirewall/resources/screenshots/\$section"
echo "done" 