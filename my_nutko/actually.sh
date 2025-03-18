#!/bin/bash
# Usage: ./scanner.sh <target> [port_range]

# Colors for output (not saved to XML)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check dependencies
for cmd in jq xargs nc curl ping xmllint; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo -e "${RED}[-] Error: '$cmd' is required. Please install it.${NC}"
        exit 1
    fi
done

# Check if target is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <target> [port_range]"
    echo "Example: $0 example.com 1-1000 or $0 history"
    exit 1
fi

TARGET=$1
PORT_RANGE=${2:-"1-1000"} # Default port range
VULN_FILES=("web_servers.json" "ssh_ftp.json" "databases.json" "runtimes.json")
TEMP_DIR=$(mktemp -d)
XML_FILE="scan_history.xml"
trap 'rm -rf "$TEMP_DIR"' EXIT # Clean up temp dir on exit

# Verify all JSON files exist
for file in "${VULN_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}[-] Error: $file not found${NC}"
        exit 1
    fi
done

# Function to initialize XML if it doesn't exist
init_xml() {
    if [ ! -f "$XML_FILE" ]; then
        echo '<?xml version="1.0" encoding="UTF-8"?><scans></scans>' > "$XML_FILE"
    fi
}

# Function to append to XML
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

# Function to read history from XML
read_history() {
    if [ ! -f "$XML_FILE" ]; then
        echo -e "${RED}[-] No scan history found${NC}"
        exit 1
    fi
    echo -e "${YELLOW}[*] Displaying scan history${NC}"
    echo "----------------------------------------"
    # Use xmllint to parse each scan
    scans=$(xmllint --xpath "count(//scan)" "$XML_FILE" 2>/dev/null)
    for ((i=1; i<=scans; i++)); do
        target=$(xmllint --xpath "string(//scan[$i]/@target)" "$XML_FILE")
        timestamp=$(xmllint --xpath "string(//scan[$i]/@timestamp)" "$XML_FILE")
        echo -e "${YELLOW}[*] Scan for $target at $timestamp${NC}"
        
        os=$(xmllint --xpath "string(//scan[$i]/os)" "$XML_FILE")
        [ -n "$os" ] && echo -e "${GREEN}[+] OS: $os${NC}"
        
        ports=$(xmllint --xpath "count(//scan[$i]/port)" "$XML_FILE")
        for ((j=1; j<=ports; j++)); do
            port_num=$(xmllint --xpath "string(//scan[$i]/port[$j]/@number)" "$XML_FILE")
            status=$(xmllint --xpath "string(//scan[$i]/port[$j]/status)" "$XML_FILE")
            echo -e "${GREEN}[+] Port $port_num: $status${NC}"
            
            service=$(xmllint --xpath "string(//scan[$i]/port[$j]/service)" "$XML_FILE")
            [ -n "$service" ] && echo -e "${YELLOW}[*] $service${NC}"
            
            version=$(xmllint --xpath "string(//scan[$i]/port[$j]/version)" "$XML_FILE")
            [ -n "$version" ] && echo -e "${GREEN}[+] Version: $version${NC}"
            
            vulns=$(xmllint --xpath "count(//scan[$i]/port[$j]/vulnerabilities/vulnerability)" "$XML_FILE")
            for ((k=1; k<=vulns; k++)); do
                vuln=$(xmllint --xpath "string(//scan[$i]/port[$j]/vulnerabilities/vulnerability[$k])" "$XML_FILE")
                echo -e "${RED}[-] $vuln${NC}"
            done
            
            checks=$(xmllint --xpath "count(//scan[$i]/port[$j]/web_checks/check)" "$XML_FILE")
            for ((l=1; l<=checks; l++)); do
                check=$(xmllint --xpath "string(//scan[$i]/port[$j]/web_checks/check[$l])" "$XML_FILE")
                echo -e "${RED}[-] $check${NC}"
            done
        done
        echo "----------------------------------------"
    done
}

# Basic OS detection using TTL
detect_os() {
    echo -e "${YELLOW}[*] Attempting OS detection...${NC}"
    ttl=$(ping -c 4 "$TARGET" | grep -o "ttl=[0-9]*" | cut -d'=' -f2 | head -n1)
    case $ttl in
        [0-64]) os="Likely Linux/Unix (TTL: $ttl)" ;;
        [65-128]) os="Likely Windows (TTL: $ttl)" ;;
        [129-255]) os="Likely Solaris/AIX (TTL: $ttl)" ;;
        *) os="Unknown OS (TTL: $ttl)" ;;
    esac
    echo -e "${GREEN}[+] OS: $os${NC}"
    echo "<os>$os</os>"
}

# Cache vulnerability lookups
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
            versions=$(jq -r ".\"$service\" | keys[]" "$file")
            for vuln_version in $versions; do
                if [[ "$vuln_version" =~ ^([0-9.]+)-([0-9.]+)$ ]]; then
                    start_ver=${BASH_REMATCH[1]}
                    end_ver=${BASH_REMATCH[2]}
                    if [[ "$version" > "$start_ver" && "$version" < "$end_ver" ]]; then
                        jq -r ".\"$service\".\"$vuln_version\"[]" "$file" | while read -r vuln; do
                            echo -e "${RED}[-] $vuln${NC}"
                            echo "<vulnerability>$vuln</vulnerability>" >> "$output_file"
                        done | tee "$cache_file"
                    fi
                elif [[ "$version" == "$vuln_version" ]]; then
                    jq -r ".\"$service\".\"$vuln_version\"[]" "$file" | while read -r vuln; do
                        echo -e "${RED}[-] $vuln${NC}"
                        echo "<vulnerability>$vuln</vulnerability>" >> "$output_file"
                    done | tee "$cache_file"
                fi
            done
        fi
    done
    [ ! -s "$cache_file" ] && touch "$cache_file"
}

# Parallel port scanning
scan_port() {
    local port=$1 output_file=$2
    if timeout 0.5 bash -c "echo > /dev/tcp/$TARGET/$port" 2>/dev/null; then
        echo -e "${GREEN}[+] Port $port is open${NC}"
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
export -f scan_port check_web_vulns check_service cache_vulns TARGET TEMP_DIR RED GREEN YELLOW NC

check_service() {
    local name=$1 port=$2 pattern=$3 output_file=$4
    echo -e "${YELLOW}[*] $name detected on port $port${NC}"
    echo "<service>$name detected on port $port</service>" >> "$output_file"
    version=$(timeout 1 nc -v "$TARGET" "$port" 2>&1 | grep -o "$pattern.*" | head -n1)
    if [ -n "$version" ]; then
        echo -e "${GREEN}[+] Version: $version${NC}"
        echo "<version>$version</version>" >> "$output_file"
        echo "<vulnerabilities>" >> "$output_file"
        cache_vulns "$version" "$output_file"
        echo "</vulnerabilities>" >> "$output_file"
    fi
}

check_web_vulns() {
    local port=$1 output_file=$2
    protocol="http"
    [ "$port" -eq 443 ] && protocol="https"
    echo -e "${YELLOW}[*] Web server detected on $protocol://$TARGET:$port${NC}"
    echo "<service>Web server detected on $protocol://$TARGET:$port</service>" >> "$output_file"
    
    server=$(curl -sI "$protocol://$TARGET:$port" | grep -i "Server:" | awk '{$1=""; print substr($0,2)}')
    if [ -n "$server" ]; then
        echo -e "${GREEN}[+] Server version: $server${NC}"
        echo "<version>$server</version>" >> "$output_file"
        echo "<vulnerabilities>" >> "$output_file"
        cache_vulns "$server" "$output_file"
        echo "</vulnerabilities>" >> "$output_file"
    fi
    
    echo "<web_checks>" >> "$output_file"
    if curl -s "$protocol://$TARGET:$port" | grep -q "Index of"; then
        echo -e "${RED}[-] Directory indexing enabled${NC}"
        echo "<check>Directory indexing enabled</check>" >> "$output_file"
    fi
    
    for file in ".htaccess" "admin.php" "config.php" "phpinfo.php"; do
        if [ "$(curl -s -o /dev/null -w "%{http_code}" "$protocol://$TARGET:$port/$file")" -eq 200 ]; then
            echo -e "${RED}[-] Found sensitive file: $file${NC}"
            echo "<check>Found sensitive file: $file</check>" >> "$output_file"
        fi
    done
    echo "</web_checks>" >> "$output_file"
}

# Main execution
if [ "$TARGET" == "history" ]; then
    read_history
    exit 0
fi

echo -e "${YELLOW}[*] Starting scan on $TARGET${NC}"
echo "----------------------------------------"

# Capture output to file
output_file="$TEMP_DIR/scan_output.xml"
: > "$output_file" # Clear output file

# OS detection
detect_os >> "$output_file"

echo -e "${YELLOW}[*] Scanning ports $PORT_RANGE (parallel)...${NC}"
IFS='-' read -r START_PORT END_PORT <<< "$PORT_RANGE"
seq "$START_PORT" "$END_PORT" | xargs -P 10 -I {} bash -c "scan_port {} '$output_file'"

echo "----------------------------------------"
echo -e "${GREEN}[+] Scan completed${NC}"

# Display output and append to XML
cat "$output_file"
append_to_xml "$TARGET" "$output_file"

exit 0
