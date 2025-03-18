#!/bin/bash

# Enable case-insensitive matching
shopt -s nocasematch

# Function to display the menu
display_menu() {
    echo "=============================="
    echo "   Network Tools Menu"
    echo "=============================="
    echo "1. Check network connectivity (ping)"
    echo "2. Trace route to a host (traceroute)"
    echo "3. Trace path to a host (tracepath)"
    echo "4. Show socket statistics (ss)"
    echo "5. Display network connections (netstat)"
    echo "6. DNS lookup (dig)"
    echo "7. DNS query (nslookup)"
    echo "8. Capture network packets (tcpdump)"
    echo "9. Display ARP table (arp)"
    echo "10. Show routing table (route)"
    echo "11. Manage network connections (NetworkManager)"
    echo "12. Display network interfaces (ifconfig)"
    echo "13. Show Ethernet device settings (ethtool)"
    echo "14. Open a network connection (nc)"
    echo "15. Manage firewall rules (iptables)"
    echo "16. Manage firewall rules (nftables)"
    echo "17. Exit"
    echo "=============================="
}

# Main loop
while true; do
    display_menu
    read -p "Enter your choice: " choice

    case $choice in
        *"check network connectivity"* | *"ping"* | *"test connectivity"* | *"check connectivity"* | *"network check"* | *"ping test"*)
            read -p "Enter the host to ping: " host
            echo "Pinging $host..."
            ping -c 4 "$host"
            ;;
        *"trace route to a host"* | *"traceroute"* | *"trace route" | *"trace route to"* | *"tracing route"*)
            read -p "Enter the host for traceroute: " host
            echo "Running traceroute to $host..."
            traceroute "$host"
            ;;
        *"trace path to a host"* | *"tracepath"* | *"path trace"* | *"tracing path"*)
            read -p "Enter the host for tracepath: " host
            echo "Running tracepath to $host..."
            tracepath "$host"
            ;;
        *"show socket statistics"* | *"socket stats"* | *"ss" | *"socket information"*)
            echo "Displaying socket statistics..."
            ss -tuln
            ;;
        *"display network connections"* | *"netstat"* | *"network connections"* | *"show connections"*)
            echo "Displaying network connections..."
            netstat -tuln
            ;;
        *"dns lookup"* | *"dig"* | *"dns query"* | *"domain lookup"* | *"lookup domain"*)
            read -p "Enter the domain for dig: " domain
            echo "Running dig for $domain..."
            dig "$domain"
            ;;
        *"dns query"* | *"nslookup"* | *"lookup domain"* | *"domain query"*)
            read -p "Enter the domain for nslookup: " domain
            echo "Running nslookup for $domain..."
            nslookup "$domain"
            ;;
        *"capture network packets"* | *"tcpdump"* | *"capture packets"* | *"packet capture"*)
            echo "Starting tcpdump (press Ctrl+C to stop)..."
            sudo tcpdump
            ;;
        *"display arp table"* | *"arp"* | *"show arp"* | *"arp table"*)
            echo "Displaying ARP table..."
            arp -a
            ;;
        *"show routing table"* | *"route"* | *"routing info"* | *"display routing table"*)
            echo "Displaying routing table..."
            route -n
            ;;
        *"manage network connections"* | *"NetworkManager"* | *"network manager"* | *"manage connections"*)
            echo "Launching NetworkManager..."
            nmcli
            ;;
        *"display network interfaces"* | *"ifconfig"* | *"network interfaces"* | *"show interfaces"*)
            echo "Displaying network interfaces..."
            ifconfig
            ;;
        *"show ethernet device settings"* | *"ethtool"* | *"ethernet settings"* | *"show eth settings"*)
            read -p "Enter the interface name for ethtool: " interface
            echo "Showing settings for $interface..."
            ethtool "$interface"
            ;;
                *"open a network connection"* | *"nc"* | *"netcat"* | *"open connection"* | *"connect to host"*)
            read -p "Enter the host and port (e.g., example.com 80): " host port
            echo "Opening connection to $host on port $port..."
            nc "$host" "$port"
            ;;
        *"manage firewall rules"* | *"iptables"* | *"firewall rules"* | *"manage iptables"*)
            echo "Choose firewall management (iptables/nftables):"
            read -p "Enter 'iptables' or 'nftables': " fw_choice
            if [[ "$fw_choice" == "iptables" ]]; then
                echo "Displaying iptables rules..."
                sudo iptables -L
            elif [[ "$fw_choice" == "nftables" ]]; then
                echo "Displaying nftables rules..."
                sudo nft list ruleset
            else
                echo "Invalid choice. Please enter 'iptables' or 'nftables'."
            fi
            ;;
        *"manage nftables"* | *"nftables"* | *"nft rules"* | *"nft management"*)
            echo "Displaying nftables rules..."
            sudo nft list ruleset
            ;;
        *"exit"* | *"quit"* | *"close"*)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid input. Please try again."
            ;;
    esac

    echo "=============================="
    read -p "Press Enter to continue..."
done
        
      
