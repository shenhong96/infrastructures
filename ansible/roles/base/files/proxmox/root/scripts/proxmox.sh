#!/bin/bash

# ============================================================================
# Proxmox Management Script
# Modern, intuitive bash script for managing Proxmox LXC containers and VMs
# ============================================================================

set -euo pipefail

# ============================================================================
# MODERN COLOR SCHEME - Check terminal support first
# ============================================================================

# Check if terminal supports colors
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]] && [[ "${TERM:-}" != "dumb" ]]; then
    # Colors enabled
    readonly RESET='\033[0m'
    readonly BOLD='\033[1m'
    readonly DIM='\033[2m'

    # Modern gradient colors
    readonly PRIMARY='\033[38;5;75m'      # Electric blue
    readonly SECONDARY='\033[38;5;147m'   # Light purple
    readonly SUCCESS='\033[38;5;84m'      # Bright green
    readonly WARNING='\033[38;5;214m'     # Orange
    readonly ERROR='\033[38;5;196m'       # Bright red
    readonly ACCENT='\033[38;5;81m'       # Cyan
    readonly MUTED='\033[38;5;244m'       # Gray

    # Background highlights
    readonly BG_HEADER='\033[48;5;235m'   # Dark gray background
    readonly BG_SUCCESS='\033[48;5;22m'   # Dark green background
    readonly BG_WARNING='\033[48;5;52m'   # Dark red background
else
    # Colors disabled
    readonly RESET=''
    readonly BOLD=''
    readonly DIM=''
    readonly PRIMARY=''
    readonly SECONDARY=''
    readonly SUCCESS=''
    readonly WARNING=''
    readonly ERROR=''
    readonly ACCENT=''
    readonly MUTED=''
    readonly BG_HEADER=''
    readonly BG_SUCCESS=''
    readonly BG_WARNING=''
fi

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Get terminal width
get_terminal_width() {
    local width
    width=$(tput cols 2>/dev/null || echo "80")
    echo "$width"
}

# Calculate display width (excluding ANSI escape codes)
display_width() {
    local text="$1"
    # Remove ANSI escape sequences and count characters
    echo -n "$text" | sed 's/\x1b\[[0-9;]*m//g' | wc -c
}

# Pad string to specified width (accounting for ANSI codes)
pad_string() {
    local text="$1"
    local target_width="$2"
    local align="${3:-left}"  # left, right, center
    
    local display_len
    display_len=$(display_width "$text")
    local padding=$((target_width - display_len))
    
    if [[ $padding -le 0 ]]; then
        echo -n "$text"
        return
    fi
    
    case "$align" in
        "right")
            printf "%*s%s" "$padding" "" "$text"
            ;;
        "center")
            local left_pad=$((padding / 2))
            local right_pad=$((padding - left_pad))
            printf "%*s%s%*s" "$left_pad" "" "$text" "$right_pad" ""
            ;;
        *)
            printf "%s%*s" "$text" "$padding" ""
            ;;
    esac
}

# Calculate optimal column widths based on terminal size
calculate_column_widths() {
    local terminal_width="$1"
    local min_widths=(6 12 12 6 8 8 12)  # Minimum widths for each column
    local headers=("ID" "NAME" "STATUS" "TYPE" "CPU" "MEMORY" "DISK FREE")
    
    # Calculate available width (minus separators)
    local separators_width=$((${#headers[@]} - 1))  # Spaces between columns
    local available_width=$((terminal_width - separators_width))
    
    # Start with minimum widths
    local widths=("${min_widths[@]}")
    local used_width=0
    for w in "${min_widths[@]}"; do
        used_width=$((used_width + w))
    done
    
    # Distribute remaining space proportionally
    local remaining=$((available_width - used_width))
    if [[ $remaining -gt 0 ]]; then
        # Give extra space to NAME and DISK FREE columns
        local name_extra=$((remaining * 40 / 100))
        local disk_extra=$((remaining * 30 / 100))
        local status_extra=$((remaining * 20 / 100))
        local mem_extra=$((remaining - name_extra - disk_extra - status_extra))
        
        widths[1]=$((widths[1] + name_extra))    # NAME
        widths[2]=$((widths[2] + status_extra))  # STATUS  
        widths[5]=$((widths[5] + mem_extra))     # MEMORY
        widths[6]=$((widths[6] + disk_extra))    # DISK FREE
    fi
    
    echo "${widths[@]}"
}

# Check if fzf is available
check_fzf() {
    command -v fzf >/dev/null 2>&1
}

print_header() {
    local title="$1"
    echo -e "\n${BG_HEADER}${BOLD}${PRIMARY} ▓▓▓ ${title} ▓▓▓ ${RESET}\n"
}

print_success() {
    echo -e "${SUCCESS}✓${RESET} $1"
}

print_error() {
    echo -e "${ERROR}✗${RESET} $1" >&2
}

print_warning() {
    echo -e "${WARNING}⚠${RESET} $1"
}

print_info() {
    echo -e "${ACCENT}ℹ${RESET} $1"
}

print_separator() {
    echo -e "${MUTED}$(printf '─%.0s' {1..80})${RESET}"
}

# Check if running as root or with proper permissions
check_permissions() {
    if ! command -v pvesh >/dev/null 2>&1; then
        print_error "Proxmox commands not found. Are you running this on a Proxmox node?"
        exit 1
    fi
}

# ============================================================================
# CORE FUNCTIONS
# ============================================================================

get_container_list() {
    # Get both LXC containers and VMs efficiently
    {
        pvesh get /nodes/$(hostname)/lxc --output-format json 2>/dev/null | \
        jq -r '.[] | "\(.vmid)|\(.name // "unnamed")|\(.status)|lxc|\(.maxmem // 0)|\(.maxdisk // 0)"' 2>/dev/null || true
        
        pvesh get /nodes/$(hostname)/qemu --output-format json 2>/dev/null | \
        jq -r '.[] | "\(.vmid)|\(.name // "unnamed")|\(.status)|qemu|\(.maxmem // 0)|\(.maxdisk // 0)"' 2>/dev/null || true
    } | sort -t'|' -k1 -n
}

get_container_metrics() {
    local vmid="$1"
    local type="$2"
    
    if [[ "$type" == "lxc" ]]; then
        pvesh get "/nodes/$(hostname)/lxc/$vmid/status/current" --output-format json 2>/dev/null | \
        jq -r '"\(.cpu // 0)|\(.mem // 0)|\(.maxmem // 1)|\(.disk // 0)|\(.maxdisk // 1)"' 2>/dev/null || echo "0|0|1|0|1"
    else
        pvesh get "/nodes/$(hostname)/qemu/$vmid/status/current" --output-format json 2>/dev/null | \
        jq -r '"\(.cpu // 0)|\(.mem // 0)|\(.maxmem // 1)|\(.disk // 0)|\(.maxdisk // 1)"' 2>/dev/null || echo "0|0|1|0|1"
    fi
}

format_bytes() {
    local bytes=$1
    if [[ $bytes -eq 0 ]]; then
        echo "0B"
        return
    fi
    
    local units=("B" "KB" "MB" "GB" "TB")
    local unit=0
    local size=$bytes
    
    while [[ $size -gt 1024 && $unit -lt 4 ]]; do
        size=$((size / 1024))
        unit=$((unit + 1))
    done
    
    echo "${size}${units[$unit]}"
}

calculate_percentage() {
    local used=$1
    local total=$2
    if [[ $total -eq 0 ]]; then
        echo "0"
    else
        echo $(( (used * 100) / total ))
    fi
}

colorize_percentage() {
    local percent=$1
    if [[ $percent -gt 80 ]]; then
        echo -e "${ERROR}${percent}%${RESET}"
    elif [[ $percent -gt 60 ]]; then
        echo -e "${WARNING}${percent}%${RESET}"
    else
        echo -e "${SUCCESS}${percent}%${RESET}"
    fi
}

colorize_status() {
    local status=$1
    case "$status" in
        "running") echo -e "${SUCCESS}●${RESET} running" ;;
        "stopped") echo -e "${ERROR}●${RESET} stopped" ;;
        "paused")  echo -e "${WARNING}●${RESET} paused" ;;
        *)         echo -e "${MUTED}●${RESET} $status" ;;
    esac
}

# ============================================================================
# MAIN FUNCTIONS
# ============================================================================

list_containers() {
    local use_fzf="${1:-false}"
    
    print_header "Proxmox Containers & VMs"
    
    # Get terminal width and calculate column widths
    local term_width
    term_width=$(get_terminal_width)
    local -a col_widths
    read -ra col_widths <<< "$(calculate_column_widths "$term_width")"
    
    # Prepare data
    local containers
    containers=$(get_container_list)
    
    if [[ -z "$containers" ]]; then
        print_warning "No containers or VMs found"
        return
    fi
    
    # If fzf is requested and available, use it
    if [[ "$use_fzf" == "true" ]] && check_fzf; then
        list_with_fzf "$containers" "${col_widths[@]}"
        return
    fi
    
    # Display table header
    printf "%s %s %s %s %s %s %s\n" \
        "$(pad_string "${BOLD}${PRIMARY}ID${RESET}" "${col_widths[0]}")" \
        "$(pad_string "${BOLD}${PRIMARY}NAME${RESET}" "${col_widths[1]}")" \
        "$(pad_string "${BOLD}${PRIMARY}STATUS${RESET}" "${col_widths[2]}")" \
        "$(pad_string "${BOLD}${PRIMARY}TYPE${RESET}" "${col_widths[3]}")" \
        "$(pad_string "${BOLD}${PRIMARY}CPU${RESET}" "${col_widths[4]}")" \
        "$(pad_string "${BOLD}${PRIMARY}MEMORY${RESET}" "${col_widths[5]}")" \
        "$(pad_string "${BOLD}${PRIMARY}DISK FREE${RESET}" "${col_widths[6]}")"
    
    # Print separator line
    local separator_char="─"
    printf "%s\n" "$(printf "${MUTED}%*s${RESET}" "$((term_width))" "" | tr ' ' "$separator_char")"
    
    # Display data rows
    while IFS='|' read -r vmid name status type maxmem maxdisk; do
        [[ -z "$vmid" ]] && continue
        
        # Get real-time metrics
        local metrics
        metrics=$(get_container_metrics "$vmid" "$type")
        IFS='|' read -r cpu_float mem_used mem_max disk_used disk_max <<< "$metrics"
        
        # Calculate percentages and format
        local cpu_percent
        cpu_percent=$(echo "$cpu_float * 100" | bc 2>/dev/null | cut -d. -f1 2>/dev/null || echo "0")
        
        local mem_percent
        mem_percent=$(calculate_percentage "$mem_used" "$mem_max")
        
        local disk_free
        disk_free=$((disk_max - disk_used))
        local disk_free_formatted
        disk_free_formatted=$(format_bytes "$disk_free")
        
        # Truncate name if too long
        local display_name="$name"
        local max_name_width=$((col_widths[1] - 3))  # Account for "..."
        if [[ $(display_width "$name") -gt $max_name_width ]]; then
            display_name="${name:0:$max_name_width}..."
        fi
        
        # Format type with color
        local type_colored
        if [[ "$type" == "lxc" ]]; then
            type_colored="${ACCENT}LXC${RESET}"
        else
            type_colored="${SECONDARY}VM${RESET}"
        fi
        
        # Display row
        printf "%s %s %s %s %s %s %s\n" \
            "$(pad_string "${BOLD}$vmid${RESET}" "${col_widths[0]}")" \
            "$(pad_string "$display_name" "${col_widths[1]}")" \
            "$(pad_string "$(colorize_status "$status")" "${col_widths[2]}")" \
            "$(pad_string "$type_colored" "${col_widths[3]}")" \
            "$(pad_string "$(colorize_percentage "$cpu_percent")" "${col_widths[4]}")" \
            "$(pad_string "$(colorize_percentage "$mem_percent")" "${col_widths[5]}")" \
            "$(pad_string "$disk_free_formatted" "${col_widths[6]}")"
            
    done <<< "$containers"
    
    # Show fzf tip if available
    if check_fzf; then
        echo ""
        print_info "💡 Use '$(basename "$0") list --fzf' or '$(basename "$0") fzf' for interactive filtering"
    fi
    
    echo ""
}

# ============================================================================
# FZF INTEGRATION
# ============================================================================

list_with_fzf() {
    local containers="$1"
    shift
    local -a col_widths=("$@")
    
    # Prepare data for fzf (without colors for clean filtering)
    local fzf_data=""
    local -a container_info=()
    
    while IFS='|' read -r vmid name status type maxmem maxdisk; do
        [[ -z "$vmid" ]] && continue
        
        # Get metrics
        local metrics
        metrics=$(get_container_metrics "$vmid" "$type")
        IFS='|' read -r cpu_float mem_used mem_max disk_used disk_max <<< "$metrics"
        
        local cpu_percent
        cpu_percent=$(echo "$cpu_float * 100" | bc 2>/dev/null | cut -d. -f1 2>/dev/null || echo "0")
        
        local mem_percent
        mem_percent=$(calculate_percentage "$mem_used" "$mem_max")
        
        local disk_free
        disk_free=$((disk_max - disk_used))
        local disk_free_formatted
        disk_free_formatted=$(format_bytes "$disk_free")
        
        # Truncate name for display
        local display_name="$name"
        local max_name_width=$((col_widths[1] - 3))
        if [[ ${#name} -gt $max_name_width ]]; then
            display_name="${name:0:$max_name_width}..."
        fi
        
        # Format for fzf (clean, no colors)
        local fzf_line
        printf -v fzf_line "%-6s %-20s %-12s %-6s %8s %8s %12s" \
            "$vmid" "$display_name" "$status" "$type" "${cpu_percent}%" "${mem_percent}%" "$disk_free_formatted"
        
        fzf_data+="$fzf_line"$'\n'
        container_info+=("$vmid|$name|$status|$type")
    done <<< "$containers"
    
    # fzf options with custom header and preview
    local fzf_header="🔍 Filter containers/VMs | Enter: Shell | Ctrl-C: Exit | Tab: Multi-select"
    
    local selected
    selected=$(echo "$fzf_data" | fzf \
        --header="$fzf_header" \
        --header-lines=0 \
        --multi \
        --reverse \
        --height=80% \
        --border=rounded \
        --prompt="🖥️  " \
        --pointer="▶" \
        --marker="✓" \
        --bind="enter:accept" \
        --bind="ctrl-a:select-all" \
        --bind="ctrl-d:deselect-all" \
        --preview="echo 'Selected: {1} - {2}' && echo 'Status: {3}' && echo 'Type: {4}'" \
        --preview-window="up:3:wrap" \
        --color="header:bold:blue,pointer:bold:cyan,marker:bold:green")
    
    if [[ -z "$selected" ]]; then
        print_info "No selection made"
        return
    fi
    
    # Process selections
    local -a selected_ids=()
    while IFS= read -r line; do
        local vmid
        vmid=$(echo "$line" | awk '{print $1}')
        selected_ids+=("$vmid")
    done <<< "$selected"
    
    if [[ ${#selected_ids[@]} -eq 1 ]]; then
        # Single selection - offer actions
        local vmid="${selected_ids[0]}"
        print_info "Selected: $vmid"
        echo ""
        echo -e "${BOLD}Choose action:${RESET}"
        echo -e "  ${PRIMARY}1${RESET} - Shell access"
        echo -e "  ${PRIMARY}2${RESET} - Find docker-compose files"
        echo -e "  ${PRIMARY}3${RESET} - Show details"
        echo ""
        
        read -p "$(echo -e "${ACCENT}Enter choice (1-3): ${RESET}")" action
        
        case "$action" in
            1) shell_access "$vmid" ;;
            2) find_docker_compose_direct "$vmid" ;;
            3) show_container_details "$vmid" ;;
            *) print_error "Invalid choice" ;;
        esac
    else
        # Multiple selections - show summary
        print_success "Selected ${#selected_ids[@]} containers:"
        for vmid in "${selected_ids[@]}"; do
            echo -e "  ${ACCENT}●${RESET} $vmid"
        done
        echo ""
        print_info "Use single selection for actions"
    fi
}

# Show detailed information about a specific container
show_container_details() {
    local vmid="$1"
    
    # Find container info
    local containers
    containers=$(get_container_list)
    local found_name="" found_status="" found_type=""
    
    while IFS='|' read -r id name status type maxmem maxdisk; do
        if [[ "$id" == "$vmid" ]]; then
            found_name="$name"
            found_status="$status"
            found_type="$type"
            break
        fi
    done <<< "$containers"
    
    if [[ -z "$found_type" ]]; then
        print_error "Container/VM $vmid not found"
        return 1
    fi
    
    print_header "Details for $found_type $vmid"
    
    echo -e "${BOLD}Basic Information:${RESET}"
    echo -e "  Name: ${ACCENT}$found_name${RESET}"
    echo -e "  Type: ${ACCENT}$found_type${RESET}"
    echo -e "  Status: $(colorize_status "$found_status")"
    echo ""
    
    # Get detailed metrics
    local metrics
    metrics=$(get_container_metrics "$vmid" "$found_type")
    IFS='|' read -r cpu_float mem_used mem_max disk_used disk_max <<< "$metrics"
    
    local cpu_percent
    cpu_percent=$(echo "$cpu_float * 100" | bc 2>/dev/null | cut -d. -f1 2>/dev/null || echo "0")
    local mem_percent
    mem_percent=$(calculate_percentage "$mem_used" "$mem_max")
    local disk_percent
    disk_percent=$(calculate_percentage "$disk_used" "$disk_max")
    
    echo -e "${BOLD}Resource Usage:${RESET}"
    echo -e "  CPU: $(colorize_percentage "$cpu_percent")"
    echo -e "  Memory: $(colorize_percentage "$mem_percent") ($(format_bytes "$mem_used")/$(format_bytes "$mem_max"))"
    echo -e "  Disk: $(colorize_percentage "$disk_percent") ($(format_bytes "$disk_used")/$(format_bytes "$disk_max"))"
    echo ""
}

# Direct docker-compose search for fzf integration
find_docker_compose_direct() {
    local vmid="$1"
    
    # Find container info
    local containers
    containers=$(get_container_list)
    local found_name="" found_status="" found_type=""
    
    while IFS='|' read -r id name status type maxmem maxdisk; do
        if [[ "$id" == "$vmid" ]]; then
            found_name="$name"
            found_status="$status"
            found_type="$type"
            break
        fi
    done <<< "$containers"
    
    if [[ "$found_status" != "running" ]]; then
        print_error "Container/VM $vmid is not running"
        return 1
    fi
    
    print_info "Searching for docker-compose files in $found_type $vmid ($found_name)..."
    
    local search_cmd="find / -type f \\( -name 'docker-compose.yml' -o -name 'docker-compose.yaml' \\) \
        -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' \
        -not -path '/run/*' -not -path '/tmp/*' 2>/dev/null || true"
    
    local results
    if [[ "$found_type" == "lxc" ]]; then
        results=$(pct exec "$vmid" -- bash -c "$search_cmd")
    else
        print_warning "Direct file search in VMs requires manual shell access"
        return 0
    fi
    
    if [[ -z "$results" ]]; then
        print_warning "No docker-compose files found"
    else
        echo -e "${SUCCESS}Found docker-compose files:${RESET}\n"
        while IFS= read -r file; do
            [[ -z "$file" ]] && continue
            echo -e "  ${ACCENT}📄${RESET} $file"
        done <<< "$results"
    fi
    echo ""
}

shell_access() {
    local target_id="$1"
    
    if [[ -z "$target_id" ]]; then
        print_header "Select Container/VM for Shell Access"
        
        # Show numbered list
        local containers
        containers=$(get_container_list)
        
        if [[ -z "$containers" ]]; then
            print_error "No containers or VMs found"
            return 1
        fi
        
        local -a options=()
        local counter=1
        
        echo -e "${BOLD}${PRIMARY}#   ID    NAME                 STATUS       TYPE${RESET}"
        print_separator
        
        while IFS='|' read -r vmid name status type maxmem maxdisk; do
            [[ -z "$vmid" ]] && continue
            
            # Truncate name for display
            local display_name
            if [[ ${#name} -gt 18 ]]; then
                display_name="${name:0:15}..."
            else
                display_name="$name"
            fi
            
            local type_colored
            if [[ "$type" == "lxc" ]]; then
                type_colored="${ACCENT}LXC${RESET}"
            else
                type_colored="${SECONDARY}VM${RESET}"
            fi
            
            printf "%s %-6s %-20s %s %s\n" \
                "${MUTED}${counter}.${RESET}" \
                "${BOLD}${vmid}${RESET}" \
                "$display_name" \
                "$(colorize_status "$status")" \
                "$type_colored"
            
            options+=("$vmid|$type|$name")
            counter=$((counter + 1))
        done <<< "$containers"
        
        echo ""
        read -p "$(echo -e "${PRIMARY}Enter selection (1-$((counter-1))) or VMID: ${RESET}")" selection
        
        # Check if it's a number (menu selection) or VMID
        if [[ "$selection" =~ ^[0-9]+$ ]] && [[ $selection -ge 1 ]] && [[ $selection -le ${#options[@]} ]]; then
            IFS='|' read -r vmid type name <<< "${options[$((selection-1))]}"
            target_id="$vmid"
        else
            target_id="$selection"
        fi
    fi
    
    # Find the container/VM details
    local containers
    containers=$(get_container_list)
    local found_type=""
    local found_name=""
    
    while IFS='|' read -r vmid name status type maxmem maxdisk; do
        if [[ "$vmid" == "$target_id" ]]; then
            found_type="$type"
            found_name="$name"
            break
        fi
    done <<< "$containers"
    
    if [[ -z "$found_type" ]]; then
        print_error "Container/VM with ID '$target_id' not found"
        return 1
    fi
    
    print_info "Connecting to $found_type $target_id ($found_name)..."
    
    if [[ "$found_type" == "lxc" ]]; then
        pct enter "$target_id"
    else
        qm terminal "$target_id"
    fi
}

find_docker_compose() {
    print_header "Find Docker Compose Files"
    
    # Show selection menu
    local containers
    containers=$(get_container_list)
    
    if [[ -z "$containers" ]]; then
        print_error "No containers or VMs found"
        return 1
    fi
    
    local -a options=()
    local counter=1
    
    echo -e "${BOLD}${PRIMARY}#   ID    NAME                 TYPE     STATUS${RESET}"
    print_separator
    
    while IFS='|' read -r vmid name status type maxmem maxdisk; do
        [[ -z "$vmid" ]] && continue
        
        # Only show running containers for file search
        [[ "$status" != "running" ]] && continue
        
        local display_name
        if [[ ${#name} -gt 18 ]]; then
            display_name="${name:0:15}..."
        else
            display_name="$name"
        fi
        
        local type_colored
        if [[ "$type" == "lxc" ]]; then
            type_colored="${ACCENT}LXC${RESET}"
        else
            type_colored="${SECONDARY}VM${RESET}"
        fi
        
        printf "%s %-6s %-20s %-8s %s\n" \
            "${MUTED}${counter}.${RESET}" \
            "${BOLD}${vmid}${RESET}" \
            "$display_name" \
            "$type_colored" \
            "$(colorize_status "$status")"
        
        options+=("$vmid|$type|$name")
        counter=$((counter + 1))
    done <<< "$containers"
    
    if [[ ${#options[@]} -eq 0 ]]; then
        print_warning "No running containers found for file search"
        return 1
    fi
    
    echo ""
    read -p "$(echo -e "${PRIMARY}Enter selection (1-$((counter-1))): ${RESET}")" selection
    
    if [[ ! "$selection" =~ ^[0-9]+$ ]] || [[ $selection -lt 1 ]] || [[ $selection -gt ${#options[@]} ]]; then
        print_error "Invalid selection"
        return 1
    fi
    
    IFS='|' read -r vmid type name <<< "${options[$((selection-1))]}"
    
    print_info "Searching for docker-compose files in $type $vmid ($name)..."
    print_separator
    
    # Optimized find command - exclude system directories for performance
    local search_cmd="find / -type f \\( -name 'docker-compose.yml' -o -name 'docker-compose.yaml' \\) \
        -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' \
        -not -path '/run/*' -not -path '/tmp/*' 2>/dev/null || true"
    
    local results
    if [[ "$type" == "lxc" ]]; then
        results=$(pct exec "$vmid" -- bash -c "$search_cmd")
    else
        # For VMs, we need to use qm terminal or SSH - this is more complex
        print_warning "Direct file search in VMs requires manual shell access"
        print_info "Use 'shell' command first, then run: $search_cmd"
        return 0
    fi
    
    if [[ -z "$results" ]]; then
        print_warning "No docker-compose files found"
    else
        echo -e "${SUCCESS}Found docker-compose files:${RESET}\n"
        while IFS= read -r file; do
            [[ -z "$file" ]] && continue
            echo -e "  ${ACCENT}📄${RESET} $file"
        done <<< "$results"
    fi
    
    echo ""
}

show_help() {
    print_header "Proxmox Management Script Help"
    
    cat << EOF
${BOLD}USAGE:${RESET}
    $0 [COMMAND] [OPTIONS]

${BOLD}COMMANDS:${RESET}
    ${PRIMARY}list${RESET}                    List all containers and VMs with metrics
    ${PRIMARY}list --fzf${RESET}              List with interactive fzf filtering
    ${PRIMARY}fzf${RESET}                     Quick access to fzf mode
    ${PRIMARY}shell${RESET} [VMID]            Access shell (interactive selection if no VMID)
    ${PRIMARY}docker-compose${RESET}          Find docker-compose files in containers
    ${PRIMARY}help${RESET}                    Show this help message

${BOLD}EXAMPLES:${RESET}
    $0                      # Interactive mode
    $0 list                 # List all containers (terminal-adaptive)
    $0 list --fzf           # List with fzf filtering
    $0 fzf                  # Quick fzf access
    $0 shell                # Interactive shell selection
    $0 shell 100            # Direct shell access to VMID 100
    $0 docker-compose       # Find docker-compose files

${BOLD}FEATURES:${RESET}
    • Real-time CPU, memory, and disk metrics
    • Terminal width-adaptive layout
    • Modern colorized output
    • fzf integration for filtering and selection
    • Support for both LXC containers and VMs
    • Fast recursive file search
    • Interactive and CLI modes

${BOLD}FZF FEATURES:${RESET}
    • Real-time filtering as you type
    • Multi-select support (Tab key)
    • Instant actions on selection
    • Preview window with container details
    • Keyboard shortcuts: Ctrl-A (select all), Ctrl-D (deselect all)

${BOLD}REQUIREMENTS:${RESET}
    • Proxmox VE environment
    • jq (JSON processor)
    • bc (calculator)
    • fzf (optional, for enhanced filtering)

EOF
}

show_interactive_menu() {
    while true; do
        print_header "Proxmox Manager - Interactive Mode"
        
        echo -e "${BOLD}Choose an option:${RESET}"
        echo -e "  ${PRIMARY}1${RESET} - List containers and VMs"
        if check_fzf; then
            echo -e "  ${PRIMARY}2${RESET} - List with fzf filtering ${ACCENT}(enhanced)${RESET}"
            echo -e "  ${PRIMARY}3${RESET} - Shell access"
            echo -e "  ${PRIMARY}4${RESET} - Find docker-compose files"
            echo -e "  ${PRIMARY}5${RESET} - Help"
            echo -e "  ${PRIMARY}q${RESET} - Quit"
        else
            echo -e "  ${PRIMARY}2${RESET} - Shell access"
            echo -e "  ${PRIMARY}3${RESET} - Find docker-compose files"
            echo -e "  ${PRIMARY}4${RESET} - Help"
            echo -e "  ${MUTED}fzf${RESET} - ${MUTED}Not available (install fzf for enhanced filtering)${RESET}"
            echo -e "  ${PRIMARY}q${RESET} - Quit"
        fi
        echo ""
        
        read -p "$(echo -e "${ACCENT}Enter your choice: ${RESET}")" choice
        
        if check_fzf; then
            case "$choice" in
                1) list_containers false ;;
                2) list_containers true ;;
                3) shell_access "" ;;
                4) find_docker_compose ;;
                5) show_help ;;
                q|Q) 
                    print_success "Goodbye!"
                    exit 0 
                    ;;
                *)
                    print_error "Invalid choice. Please try again."
                    ;;
            esac
        else
            case "$choice" in
                1) list_containers false ;;
                2) shell_access "" ;;
                3) find_docker_compose ;;
                4) show_help ;;
                q|Q) 
                    print_success "Goodbye!"
                    exit 0 
                    ;;
                *)
                    print_error "Invalid choice. Please try again."
                    ;;
            esac
        fi
        
        echo ""
        read -p "$(echo -e "${MUTED}Press Enter to continue...${RESET}")" 
    done
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    check_permissions
    
    case "${1:-}" in
        "list")
            if [[ "${2:-}" == "--fzf" ]] || [[ "${2:-}" == "-f" ]]; then
                list_containers true
            else
                list_containers false
            fi
            ;;
        "fzf")
            if check_fzf; then
                list_containers true
            else
                print_error "fzf is not installed. Please install fzf first:"
                print_info "Ubuntu/Debian: sudo apt install fzf"
                print_info "CentOS/RHEL: sudo yum install fzf"
                print_info "Or visit: https://github.com/junegunn/fzf#installation"
                exit 1
            fi
            ;;
        "shell")
            shell_access "${2:-}"
            ;;
        "docker-compose")
            find_docker_compose
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        "")
            show_interactive_menu
            ;;
        *)
            print_error "Unknown command: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
