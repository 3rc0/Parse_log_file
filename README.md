# Parse_log_file
Parsing Log Files for Secure/Auth Events in Linux OS

- [X] Parsing the log file for ( User, Public Key, Password attempt, Failed Logins ) from secure or auth.log file.
- [X] The script works on Linux OS.
- [X] Configure Cron Job to execute every Sunday at 4.05 AM.
- [X] The output saving in the Report File.

## Part 1:
Define the paths for source and target files
```console
SOURCE_SECURE_LOG="/home/redhat/Desktop/secure"
SOURCE_AUTH_LOG="/home/redhat/Desktop/report/au.log"
TARGET_FILE="/home/redhat/Desktop/report_file"
```
Initialize the source file variable
```console
SOURCE_FILE=""
```
Check if the source secure log file exists
```console
if [[ -f "$SOURCE_SECURE_LOG" ]]; then
    SOURCE_FILE="$SOURCE_SECURE_LOG"
fi
```
If the source secure log file doesn't exist, check if the source auth log file exists
```console
if [[ -z "$SOURCE_FILE" && -f "$SOURCE_AUTH_LOG" ]]; then
    SOURCE_FILE="$SOURCE_AUTH_LOG"
fi

If no valid source file is found, append an error message to the target file and exit
```console
if [[ -z "$SOURCE_FILE" ]]; then
    echo "No valid source file found." >> "$TARGET_FILE"
    exit 1
fi
....
```
The first portion is to indicate the file to be read and the second portion is to indicate the directory to be saved.
```console
"$SOURCE_FILE" >> "$TARGET_FILE"
```
## Part 2:
AWK script for data processing
```console
awk ' '
```
## Part 3:
### First Condition
This condition to handle record lines with the keyword ( Failed password and
Accepted password with Accepted password) And must be the number of 
fields are 14 or 16.
```console
Aug  7 10:49:26 hpcl003 sshd[21237]: Failed password for cdef9012 from xx.xx.xx.xx port 63470 ssh2
Aug  6 04:03:01 hpcl003 sshd[28580]: Accepted publickey for OPERA from xx.xx.xx.xx port 56632 ssh2: RSA nn:nn:nn:nn:nn:nn:nn:nn:nn:nn:nn:nn:nn:nn:nn:nn
Aug  6 08:37:41 hpcl003 sshd[2326]: Accepted password for OPERA from xx.xx.xx.xx port 36064 ssh2 
```
```console
/Failed password|Accepted (password|publickey)/ && ( NF == 14 || NF == 16 ) {
        USERS[$9] = 1
        if ($0 ~ /publickey/) {
            KEYS[$9] = $16
        } else if ($0 ~ /Failed password/) {
            FAILED_LOGINS[$9]++
            PASSWORD_ATTEMPT[$9]++
        }
    }
```
### Second Condition
This condition will handle record lines with the keyword ( Session opened & Session 
closed) And must be the number of fields are 11 or 13.
```console
Aug  6 04:03:01 hpcl003 sshd[28580]: pam_unix(sshd:session): session opened for user OPERA by (uid=0)
Aug  6 04:03:02 hpcl003 sshd[28580]: pam_unix(sshd:session): session closed for user OPERA
```
```console
/session (opened|closed)/ && ( NF == 11 || NF == 13 ) {
        sub(/\(.*/, "", $11)
        USERS[$11] = 1
    }
```
### Third Condition
This condition will handle record lines with the keyword ( authentication failure) And 
must be the number of the field is 15.
```console
Aug  8 15:20:10 hpcl004 sshd[12345]: pam_sss(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10-18-72-99.ddhcp.uni-oldenburg.de user=abcd5678
```
```console
/authentication failure/ && ( NF == 15 ) {
        sub(/.*=/, "", $NF)
        USERS[$NF] = 1
        FAILED_LOGINS[$NF]++
    }
```
### Fourth Condition    
This condition will handle record lines with the keyword ( Failure) And must be the
number of fields is 15.
```console
Aug 10 09:19:28 hpcl003 sshd[1321]: pam_sss(sshd:auth): received for user opqr1357: 17 (Failure setting user credentials)
```
```console
/Failure/ && ( NF == 15 ) {
        sub(/:$/, "", $10)
        USERS[$10] = 1
        FAILED_LOGINS[$10]++
    }
```
## Part 4
Print the header first and after that the results of the conditions, and at the end the full
path for the file target and destination to save it.
```console
END {
        printf "%-10s %-50s %-10s %-12s\n\n", "User", "Public Key", "Password", "Failed Logins"
        for (USER in USERS) {
            printf "%-10s %-50s %-10s %-12s\n", USER, KEYS[USER], PASSWORD_ATTEMPT[USER], FAILED_LOGINS[USER]
        }
    }
```
## Part 5:
Step 2: Setup a Cron job
Because the origin file from system with privilege permission for superuser only also keeping the data
with same attribute for case only authorized personnel to access to it.
```console
sudo crontab -u root -e
5 4 * * 0 /home/redhat/Desktop/parse_log_file.sh
```
