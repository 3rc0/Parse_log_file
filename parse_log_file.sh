#!/bin/bash

# Shell Script for Parsing log file
# Version v 2
# Step 1: Parse log file:
# A full path to get the logs /var/log/secure or /var/log/auth.log

# Define the paths for source and target files
SOURCE_SECURE_LOG="/home/redhat/Desktop/secure"         # /var/log/secure
SOURCE_AUTH_LOG="/home/redhat/Desktop/report/au.log"    # /var/log/auth.log
TARGET_FILE="/home/redhat/Desktop/report_file"

# Initialize the source file variable
SOURCE_FILE=""

# Check if the source secure log file exists
if [[ -f "$SOURCE_SECURE_LOG" ]]; then
    SOURCE_FILE="$SOURCE_SECURE_LOG"
fi

# If the source secure log file doesn't exist, check if the source auth log file exists
if [[ -z "$SOURCE_FILE" && -f "$SOURCE_AUTH_LOG" ]]; then
    SOURCE_FILE="$SOURCE_AUTH_LOG"
fi

# If no valid source file is found, append an error message to the target file and exit
if [[ -z "$SOURCE_FILE" ]]; then
    echo "No valid source file found." >> "$TARGET_FILE"
    exit 1
fi

# AWK script for data processing
awk '
# This condition handles record lines with the keywords "Failed password" and
# "Accepted password" (including publickey). It checks for the number of fields
# to be 14 or 16.
/Failed password|Accepted (password|publickey)/ && ( NF == 14 || NF == 16 ) {
        USERS[$9] = 1
        if ($0 ~ /publickey/) {
            split($0, parts, ": ")
            KEYS[$9] = $16
        } else if ($0 ~ /Failed password/) {
            split($0, parts, ": ")
            FAILED_LOGINS[$9]++
            PASSWORD_ATTEMPT[$9]++
        }
    }

# This condition handles record lines with the keywords "Session opened" and "Session closed".
# It checks for the number of fields to be 11 or 13.
/session (opened|closed)/ && ( NF == 11 || NF == 13 ) {
        gsub(/\(.*/, " ", $11)
        USERS[$11] = 1
    }

# This condition handles record lines with the keyword "authentication failure". It checks for
# the number of fields to be 15.
/authentication failure/ && ( NF == 15 ) {
        split($0, parts, "=")
        USERS[parts[8]] = 1
        FAILED_LOGINS[parts[8]]++
    }

# This condition handles record lines with the keyword "Failure". It checks for the number
# of fields to be 15.
/Failure/ && ( NF == 15 ) {
        sub(/:$/, "", $10)
        USERS[$10] = 1
        FAILED_LOGINS[$10]++
    }

# Print the header and results, followed by the target file path for saving.

END {
        printf "%-10s %-50s %-10s %-12s\n\n", "User", "Public Key", "Password", "Failed Logins"
        for (USER in USERS) {
            printf "%-10s %-50s %-10s %-12s\n", USER, KEYS[USER], PASSWORD_ATTEMPT[USER], FAILED_LOGINS[USER]
        }
    }
' "$SOURCE_FILE" >> "$TARGET_FILE"

# Step 2: Setup a Cron job
# Because the origin file from system with privilege permission for superuser only also keeping the data
# with same attribute for case only authorized personnel to access to it.
# sudo crontab -u root -e
# 5 4 * * 0 /home/redhat/Desktop/parse_log_file.sh
