#!/bin/bash

# Shell Script for Parsing log file
# Version v 0.1
# Step 1: Parse log file:
# A full path to get the logs /var/log/secure or /var/log/auth.log

awk '

# This condition to handle record lines with the keyword ( Failed password and
# Accepted password with Accepted password) And must be the number of 
# fields is 14 or 16.
/Failed password|Accepted (password|publickey)/ && ( NF == 14 || NF == 16 ) {
        USERS[$9] = 1
        if ($0 ~ /publickey/) {
            split($0, parts, ": ")
            KEYS[$9] = $16
        }else if ($0 ~ /Failed password/) {
            split($0, parts, ": ")
            FAILED_LOGINS[$9]++
            PASSWORD_ATTEMPT[$9]++
        }
    }

# This condition will handle record lines with the keyword ( Session opened & Session 
# closed) And must be the number of fields is 11 or 13.
/session (opened|closed)/ && ( NF == 11 || NF == 13 ) {
        USERS[$11] = 1
    }

# This condition will handle record lines with the keyword ( authentication failure) And 
# must be the number of the field is 15.
/authentication failure/ && ( NF == 15 ) {
        split($0, parts, "=")
        USERS[parts[8]] = 1
        FAILED_LOGINS[parts[8]]++
    }

# This condition will handle record lines wth te keyword ( Failure) And must to be the
# number of fields is 15.
/Failure/ && ( NF == 15 ) {
        sub(/:$/, "", $10)
        USERS[$10] = 1
        FAILED_LOGINS[$10]++
    }

# Print the header first and after that the results of the conditions, and at the end the full
# path for the file target and destination to save it.
END {
        printf "%-10s %-50s %-10s %-12s\n\n", "User", "Public Key", "Password", "Failed Logins"
        for (USER in USERS) {
            printf "%-10s %-50s %-10s %-12s\n", USER, KEYS[USER], PASSWORD_ATTEMPT[USER], FAILED_LOGINS[USER]
        }
    }
' /home/redhat/Desktop/secure >> /home/redhat/Desktop/Report_file

# Step 2: Setup a Cron job
# Because the origin file from system with privilege permission for superuser only also keeping the data
# with same attribute for case only authorized personnel to access to it.
# sudo crontab -u root -e
# 5 4 * * 0 /home/redhat/Desktop/parse_log_file_v1.sh