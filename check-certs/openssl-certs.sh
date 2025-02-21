#!/bin/bash

# Make sure only root can run our script
if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
fi

today=$(date +%Y-%m-%d)
tstoday=$(date -d "$today" +%s)
localip=$(ip a | grep 192 | awk '{print $2}' | sed 's/\/24//')

### Full FS '/' scan
find /etc -type f -name "*.pem" | grep -v '/usr/share/ca-certificates/' | grep -v '/usr/lib/python3' | grep -v '/var/lib/mysql' | grep -v '/snap/' > pem.files
find /etc -type f -name "*.crt" | grep -v '/usr/share/ca-certificates/' | grep -v '/usr/lib/python3' | grep -v '/var/lib/mysql' | grep -v '/snap/' > crt.files

### Nginx
grep --exclude="*.types" -rn .pem /etc/nginx | awk '{print $3}' | sed 's/;/\ /' > nginx.certs
grep --exclude="*.types" -rn .crt /etc/nginx | awk '{print $3}' | sed 's/;/\ /' >> nginx.certs

### Active Net ports
netstat -tulpn | grep -v ::: | grep tcp | awk '{print $4}' | grep -v '0\.0\.0\.0' | grep -v '127\.0\.0\.' > ipport.txt

echo "Local IP address is $localip"

parse_date() {
	if [[ -n "$1" ]]; then
                        month=$(echo $1 | sed 's/notAfter=//' | awk '{print $1}')
                        year=$(echo $1 | sed 's/notAfter=//' | awk '{print $4}')
                        day=$(echo $1 | sed 's/notAfter=//' | awk '{print $2}')
                        case $month in
                                Jan)
                                        mn="01"
                                        ;;
                                Feb)
                                        mn="02"
                                        ;;
                                Mar)
                                        mn="03"
                                        ;;
                                Apr)
                                        mn="04"
                                        ;;
                                May)
                                        mn="05"
                                        ;;
                                Jun)
                                        mn="06"
                                        ;;
                                Jul)
                                        mn="07"
                                        ;;
                                Aug)
                                        mn="08"
                                        ;;
                                Sep)
                                        mn="09"
                                        ;;
                                Oct)
                                        mn="10"
                                        ;;
                                Nov)
                                        mn="11"
                                        ;;
                                Dec)
                                        mn="12"
                                        ;;
                        esac
                        certexpirydate="$year-$mn-$day"
                        tscertexpirydate=$(date -d "$certexpirydate" +%s)
                        echo "Certificate in $line valid until $certexpirydate"
                        deltadays=$(((tscertexpirydate-tstoday)/86400))
                        echo "$deltadays days remaining to certificate expiry date"
                fi
}

parse_certificates() {
	while IFS= read line
	do
		if echo "$line" | grep -q "\/"; then
			opsslcertexpdate=$(echo $line | xargs -i -n 1 openssl x509 -noout -enddate -in {} 2> /dev/null)
		elif echo "$line" | grep -q "\:"; then
			opsslcertexpdate=$(echo | openssl s_client -connect "$line" 2>&1 | openssl x509 -noout -enddate 2>/dev/null)
		fi
		if [[ -n "$opsslcertexpdate" ]]; then
			parse_date "$opsslcertexpdate"
			echo ""
		fi
	done < $1
}


parse_certificates ipport.txt
parse_certificates pem.files
parse_certificates crt.files
parse_certificates nginx.certs
