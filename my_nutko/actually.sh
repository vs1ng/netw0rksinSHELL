#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

for cmd in jq xargs nc curl ping xmllint; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo -e "${RED}[-] Error: '$cmd' is required. Please install it.${NC}"
        exit 1
    fi
done

if [ -z "$1" ]; then
    echo "Usage: $0 <target> [port_range]"
    exit 1
fi

TARGET=$1
PORT_RANGE=${2:-"1-1000"}
VULN_FILES=("web_servers.json" "ssh_ftp.json" "databases.json" "runtimes.json")
TEMP_DIR=$(mktemp -d)
XML_FILE="scan_history.xml"
trap 'rm -rf "$TEMP_DIR"' EXIT

for file in "${VULN_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}[-] Error: $file not found${NC}"
        exit 1
    fi
done

init_xml() {
    if [ ! -f "$XML_FILE" ]; then
        echo '<?xml version="1.0" encoding="UTF-8"?><scans></scans>' > "$XML_FILE"
    fi
}

append_to_xml() {
    local target=$1
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local content_file=$2
    init_xml
    temp_xml="$TEMP_DIR/temp.xml"
    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo '<scans>'
        grep -v '</scans>' "$XML_FILE"
        echo "  <scan target=\"$target\" timestamp=\"$timestamp\">"
        cat "$content_file" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'\''/\&apos;/g'
        echo '  </scan>'
        echo '</scans>'
    } > "$temp_xml"
    mv "$temp_xml" "$XML_FILE"
}

read_history() {
    if [ ! -f "$XML_FILE" ]; then
        echo -e "${RED}[-] No scan history found${NC}"
        exit 1
    fi
    xmllint --format "$XML_FILE"
}

detect_os() {
    ttl=$(ping -c 4 "$TARGET" | grep -o "ttl=[0-9]*" | cut -d'=' -f2 | head -n1)
    case $ttl in
        [0-64]) os="Linux/Unix (TTL: $ttl)" ;;
        [65-128]) os="Windows (TTL: $ttl)" ;;
        [129-255]) os="Solaris/AIX (TTL: $ttl)" ;;
        *) os="Unknown OS (TTL: $ttl)" ;;
    esac
    echo "<os>$os</os>"
}

cache_vulns() {
    local service_version=$1 output_file=$2
    local cache_file="$TEMP_DIR/$(echo "$service_version" | tr '/' '_').cache"
    if [ -f "$cache_file" ]; then
        cat "$cache_file" >> "$output_file"
        return
    fi
    service=$(echo "$service_version" | cut -d'/' -f1 | tr -d ' ')
    version=$(echo "$service_version" | cut -d'/' -f2- | tr -d ' ')
    for file in "${VULN_FILES[@]}"; do
        if jq -e ".\"$service\"" "$file" >/dev/null 2>&1; then
            jq -r ".\"$service\"."$version"[]" "$file" | while read -r vuln; do
                echo "<vulnerability>$vuln</vulnerability>" >> "$output_file"
            done | tee "$cache_file"
        fi
    done
    [ ! -s "$cache_file" ] && touch "$cache_file"
}

scan_port() {
    local port=$1 output_file=$2
    if timeout 0.5 bash -c "echo > /dev/tcp/$TARGET/$port" 2>/dev/null; then
        {
            echo "<port number=\"$port\">"
            echo "<status>open</status>"
            case $port in
                80|443) check_web_vulns "$port" "$output_file" ;;
                22) check_service "SSH" "$port" "OpenSSH" "$output_file" ;;
                21) check_service "FTP" "$port" "vsftpd" "$output_file" ;;
                3306) check_service "MySQL" "$port" "MySQL" "$output_file" ;;
                5432) check_service "PostgreSQL" "$port" "PostgreSQL" "$output_file" ;;
            esac
            echo "</port>"
        } >> "$output_file"
    fi
}
export -f scan_port check_web_vulns check_service cache_vulns TARGET TEMP_DIR

check_service() {
    local name=$1 port=$2 pattern=$3 output_file=$4
    version=$(timeout 1 nc -v "$TARGET" "$port" 2>&1 | grep -o "$pattern.*" | head -n1)
    if [ -n "$version" ]; then
        echo "<service>$name</service><version>$version</version>" >> "$output_file"
        echo "<vulnerabilities>" >> "$output_file"
        cache_vulns "$version" "$output_file"
        echo "</vulnerabilities>" >> "$output_file"
    fi
}

check_web_vulns() {
    local port=$1 output_file=$2
    protocol="http"
    [ "$port" -eq 443 ] && protocol="https"
    server=$(curl -sI "$protocol://$TARGET:$port" | grep -i "Server:" | awk '{$1=""; print substr($0,2)}')
    if [ -n "$server" ]; then
        echo "<service>Web server</service><version>$server</version>" >> "$output_file"
        echo "<vulnerabilities>" >> "$output_file"
        cache_vulns "$server" "$output_file"
        echo "</vulnerabilities>" >> "$output_file"
    fi
}

if [ "$TARGET" == "history" ]; then
    read_history
    exit 0
fi

output_file="$TEMP_DIR/scan_output.xml"
: > "$output_file"

detect_os >> "$output_file"

IFS='-' read -r START_PORT END_PORT <<< "$PORT_RANGE"
seq "$START_PORT" "$END_PORT" | xargs -P 10 -I {} bash -c "scan_port {} '$output_file'"

cat "$output_file"
append_to_xml "$TARGET" "$output_file"

exit 0