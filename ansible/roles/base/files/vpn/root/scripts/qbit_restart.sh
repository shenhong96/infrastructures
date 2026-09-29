#!/bin/bash

# Configuration
LOG_FILE=~/update_restart.log
SCRIPT_LOG="/tmp/update_restart.sh.logs"
CUSTOM_SCRIPT="/root/scripts/update_restart.sh"
ONE_DAY_IN_SECONDS=86400

# Function to log messages with timestamp
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$SCRIPT_LOG"
}

# Function to check if a file is older than 24 hours
# Returns: 0 (true) if file is older than 24 hours, 1 (false) otherwise
check_file_age() {
    local file="$1"
    local current_time=$(date +%s)
    local file_time=0
    
    # Get file modification time, handling both Linux and MacOS
    if [ -f "$file" ]; then
        file_time=$(stat -c %Y "$file" 2>/dev/null)
    fi
    
    local time_diff=$((current_time - file_time))
    
    [ $time_diff -gt $ONE_DAY_IN_SECONDS ]
}

# Function to run custom script and update log
# Returns: 0 on success, 1 on failure
run_custom_script() {
    touch "$LOG_FILE"
    if [ ! -f "$CUSTOM_SCRIPT" ]; then
        log_message "Error: Custom script not found at: $CUSTOM_SCRIPT"
        return 1
    fi

    log_message "Running custom script..."
    if bash "$CUSTOM_SCRIPT" "restart"; then
        log_message "Custom script executed successfully"
        log_message "Updated timestamp in log file"
        return 0
    else
        log_message "Error: Custom script failed"
        return 1
    fi
}

# Main script execution
main() {
    # Create or truncate the log file at the start of each run
    log_message "Starting script execution"
    
    # Check if Docker curl command fails
    if docker exec qbittorrent curl -s ifconfig.me > /dev/null; then
        log_message "Connectivity check successful"
        return 0
    fi

    log_message "Connectivity check failed, checking log file age..."
    
    # Only proceed if log file is older than 24 hours
    if ! check_file_age "$LOG_FILE"; then
        log_message "Log file is less than 24 hours old, skipping custom script execution"
        return 0
    fi

    # Run custom script and update log
    run_custom_script
}

# Execute main function
main
