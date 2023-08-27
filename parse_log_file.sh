#!/bin/bash

# Shell Script for Parsing log file
# Version v 3
# Step 1: Parse log file:
# A full path to get the logs /var/log/secure or /var/log/auth.log


SOURCE_SECURE_LOG="/home/redhat/Desktop/secure"         # /var/log/secure
SOURCE_AUTH_LOG="/home/redhat/Desktop/report/au.log"    # /var/log/auth.log
TARGET_FILE="/home/redhat/Desktop/report_file"


SOURCE_FILE=""

if [[ -f "$SOURCE_SECURE_LOG" ]]; then
    SOURCE_FILE="$SOURCE_SECURE_LOG"
fi

if [[ -z "$SOURCE_FILE" && -f "$SOURCE_AUTH_LOG" ]]; then
    SOURCE_FILE="$SOURCE_AUTH_LOG"
fi

if [[ -z "$SOURCE_FILE" ]]; then
    echo "No valid source file found." >> "$TARGET_FILE"
    exit 1
fi

awk '

/Failed password|Accepted (password|publickey)/ && ( NF == 14 || NF == 16 ) {
        USERS[$9] = 1
        if ($0 ~ /publickey/) {
            KEYS[$9] = $16
        } else if ($0 ~ /Failed password/) {
            FAILED_LOGINS[$9]++
            PASSWORD_ATTEMPT[$9]++
        }
    }

/session (opened|closed)/ && ( NF == 11 || NF == 13 ) {
        sub(/\(.*/, " ", $11)
        USERS[$11] = 1
    }

/authentication failure/ && ( NF == 15 ) {
        sub(/.*=/, "", $NF)
        USERS[parts[8]] = 1
        FAILED_LOGINS[parts[8]]++
    }

/Failure/ && ( NF == 15 ) {
        sub(/:$/, "", $10)
        USERS[$10] = 1
        FAILED_LOGINS[$10]++
    }

END {
        printf "%-10s %-50s %-10s %-12s\n\n", "User", "Public Key", "Password", "Failed Logins"
        for (USER in USERS) {
            printf "%-10s %-50s %-10s %-12s\n", USER, KEYS[USER], PASSWORD_ATTEMPT[USER], FAILED_LOGINS[USER]
        }
    }
' "$SOURCE_FILE" >> "$TARGET_FILE"

# Step 2: Setup a Cron job
# Because the origin file from the system with privileged permission for superuser only also keeping the data
# with the same attribute for cases only authorized personnel to access it.
# sudo crontab -u root -e
# 5 4 * * 0 /home/redhat/Desktop/parse_log_file.sh
