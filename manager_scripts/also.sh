#!/bin/bash

# Function to display the menu
display_menu() {
    echo "-----------------------------------------"
    echo "          Network Management Menu       "
    echo "-----------------------------------------"
    echo "1. Check Network Status"
    echo "2. Ping a Host"
    echo "3. List Firewall Rules"
    echo "4. Add Firewall Rule"
    echo "5. Remove Firewall Rule"
    echo "6. Flush All Firewall Rules"
    echo "7. Manage Anon CLI"
    echo "8. View Network Statistics"
    echo "9. Port Scanner"
    echo "10. Vulnerability Scanner"
    echo "11. Web Vulnerability Scanner"
    echo "12. Exit"
    echo "-----------------------------------------"
}

# Function to check network status
check_network_status() {
    echo "Checking network status..."
    ip a
    echo "-----------------------------------------"
}

# Function to ping a host
ping_host() {
    read -p "Enter the host to ping (IP or domain): " host
    echo "Pinging $host..."
    ping -c 4 "$host"
    echo "-----------------------------------------"
}

# Function to list firewall rules
list_firewall_rules() {
    echo "Listing current firewall rules..."
    sudo iptables -L -v -n
    echo "-----------------------------------------"
}

# Function to add a firewall rule
add_firewall_rule() {
    read -p "Enter the rule (e.g., INPUT -s 192.168.1.100 -j ACCEPT): " rule
    echo "Adding firewall rule: $rule"
    sudo iptables $rule
    echo "Rule added."
    echo "-----------------------------------------"
}

# Function to remove a firewall rule
remove_firewall_rule() {
    read -p "Enter the rule to remove (e.g., INPUT -s 192.168.1.100 -j ACCEPT): " rule
    echo "Removing firewall rule: $rule"
    sudo iptables -D $rule
    echo "Rule removed."
    echo "-----------------------------------------"
}

# Function to flush all firewall rules
flush_firewall_rules() {
    echo "Flushing all firewall rules..."
    sudo iptables -F
    echo "All rules flushed."
    echo "-----------------------------------------"
}

# Function to manage Anon CLI
manage_anon_cli() {
    echo "Managing Anon CLI..."
    echo "Available commands:"
    echo "1. Start Anon CLI"
    echo "2. Stop Anon CLI"
    echo "3. Status of Anon CLI"
    echo "4. Back to main menu"
    
    read -p "Select an option (1-4): " anon_option

    case $anon_option in
        1)
            echo "Starting Anon CLI..."
            anon-cli start
            ;;
        2)
            echo "Stopping Anon CLI..."
            anon-cli stop
            ;;
        3)
            echo "Checking status of Anon CLI..."
            anon-cli status
            ;;
        4)
            return
            ;;
        *)
            echo "Invalid option. Please select a number between 1 and 4."
            ;;
    esac
    echo "-----------------------------------------"
}

# Function to view network statistics
view_network_statistics() {
    echo "Viewing network statistics..."
    echo "-----------------------------------------"
    # Using 'ip -s link' to show statistics
    ip -s link
    echo "-----------------------------------------"
}

# Function for a simple port scanner
port_scanner() {
    read -p "Enter the host to scan (IP or domain): " host
    read -p "Enter the starting port (e.g., 1): " start_port
    read -p "Enter the ending port (e.g., 1024): " end_port

    echo "Scanning $host for open ports from $start_port to $end_port..."
    for ((port=start_port; port<=end_port; port++)); do
        # Use /dev/tcp to check if the port is open
        (echo > /dev/tcp/$host/$port) &>/dev/null
        if [ $? -eq 0 ]; then
            echo "Port $port is open."
        else
            echo "Port $port is closed."
        fi
    done
    echo "-----------------------------------------"
}

# Function for a basic vulnerability scanner
vulnerability_scanner() {
    echo "Running basic vulnerability scan..."
    echo "-----------------------------------------"

    # Check for open ports
    echo "Checking for open ports..."
    for port in {1..1024}; do
                (echo > /dev/tcp/localhost/$port) &>/dev/null
        if [ $? -eq 0 ]; then
            echo "Port $port is open."
        fi
    done

    # Check for outdated packages
    echo "Checking for outdated packages..."
    outdated_packages=$(apt list --upgradable 2>/dev/null | grep -E 'upgradable from')
    if [ -z "$outdated_packages" ]; then
        echo "No outdated packages found."
    else
        echo "Outdated packages found:"
        echo "$outdated_packages"
    fi

    # Check for weak file permissions on sensitive files
    echo "Checking file permissions on sensitive files..."
    sensitive_files=("/etc/passwd" "/etc/shadow" "/etc/ssh/sshd_config")
    for file in "${sensitive_files[@]}"; do
        if [ -e "$file" ]; then
            permissions=$(ls -l "$file" | awk '{print $1}')
            if [[ "$permissions" != "-rw-------" && "$permissions" != "-r--------" ]]; then
                echo "Warning: $file has weak permissions: $permissions"
            else
                echo "$file has secure permissions: $permissions"
            fi
        else
            echo "$file does not exist."
        fi
    done

    echo "Vulnerability scan completed."
    echo "-----------------------------------------"
}

# Function for a basic web vulnerability scanner
web_vulnerability_scanner() {
    echo "Running web vulnerability scan..."
    echo "-----------------------------------------"

    # Check if URL is provided
    read -p "Enter the URL to scan (e.g., http://example.com): " url

    # Function to check HTTP methods
    check_http_methods() {
        echo "Checking HTTP methods for $url..."
        methods=("GET" "POST" "PUT" "DELETE" "OPTIONS" "HEAD")
        for method in "${methods[@]}"; do
            response=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$url")
            echo "Method $method: $response"
        done
        echo "-----------------------------------------"
    }

    # Function to check for common files
    check_common_files() {
        echo "Checking for common files on $url..."
        common_files=("robots.txt" "admin.php" "config.php" "login.php" "test.php")
        for file in "${common_files[@]}"; do
            response=$(curl -s -o /dev/null -w "%{http_code}" "$url/$file")
            if [ "$response" -eq 200 ]; then
                echo "Found: $file (HTTP $response)"
            else
                echo "Not Found: $file (HTTP $response)"
            fi
        done
        echo "-----------------------------------------"
    }

    # Function to check SSL/TLS support
    check_ssl() {
        echo "Checking SSL/TLS support for $url..."
        if echo "$url" | grep -q "^https://"; then
            echo "SSL/TLS is enabled."
        else
            echo "SSL/TLS is not enabled."
        fi
        echo "-----------------------------------------"
    }

    # Function to check HTTP headers
    check_http_headers() {
        echo "Checking HTTP headers for $url..."
        headers=$(curl -s -I "$url")
        echo "$headers"
        echo "-----------------------------------------"
    }

    # Run web vulnerability checks
    check_http_methods
    check_common_files
    check_ssl
    check_http_headers
}

# Main script loop
while true; do
    display_menu
    read -p "Select an option (1-12): " option

    case $option in
        1)
            check_network_status
            ;;
        2)
            ping_host
            ;;
        3)
            list_firewall_rules
            ;;
        4)
            add_firewall_rule
            ;;
        5)
            remove_firewall_rule
            ;;
        6)
            flush_firewall_rules
            ;;
        7)
            manage_anon_cli
            ;;
        8)
            view_network_statistics
            ;;
        9)
            port_scanner
            ;;
        10)
            vulnerability_scanner
            ;;
        11)
            web_vulnerability_scanner
            ;;
        12)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option. Please select a number between 1 and 12."
            ;;
    esac
done
