#!/bin/bash

# Make sure only root can run our script
if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
fi

today=$(date +%Y-%m-%d)
tstoday=$(date -d "$today" +%s)
localip=$(ip a | grep 192 | awk '{print $2}' | sed 's/\/24//')

find /etc -type f -name "*.pem" | grep -v '/usr/share/ca-certificates/' | grep -v '/usr/lib/python3' | grep -v '/var/lib/mysql' | grep -v '/snap/' > pem.files
find /etc -type f -name "*.crt" | grep -v '/usr/share/ca-certificates/' | grep -v '/usr/lib/python3' | grep -v '/var/lib/mysql' | grep -v '/snap/' > crt.files

###Nginx
grep -rn .pem\; /etc/nginx | awk '{print $3}'
grep -rn .crt\; /etc/nginx | awk '{print $3}'

netstat -tulpn | grep -v ::: | grep tcp | awk '{print $4}' | sed s/:/\ / > ipport.txt

echo "Local IP address is $localip"

while IFS=' ' read ip port
do
	if [[ $ip == $localip ]]; then
		echo "$ip $port"
		###openssl s_client -connect "$ip:$port" 2>&1 | openssl x509 -noout -dates 2>/dev/null
		opsslcertexpdate=$(openssl s_client -connect "$ip:$port" 2>&1 | openssl x509 -noout -enddate 2>/dev/null)
		month=$(echo $opsslcertexpdate | sed 's/notAfter=//' | awk '{print $1}')
		year=$(echo $opsslcertexpdate | sed 's/notAfter=//' | awk '{print $4}')
		day=$(echo $opsslcertexpdate | sed 's/notAfter=//' | awk '{print $2}')
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
		echo "Certificate is valid until $certexpirydate"
	else
		sleep .001
	fi
done < ipport.txt

certificateparsing() {
	for line in $(cat $1)
	do
		opsslcertexpdate=$(echo $line | xargs -i -n 1 openssl x509 -noout -enddate -in {} 2> /dev/null)
		if [ -n "$opsslcertexpdate" ]; then
			month=$(echo $opsslcertexpdate | sed 's/notAfter=//' | awk '{print $1}')
			year=$(echo $opsslcertexpdate | sed 's/notAfter=//' | awk '{print $4}')
			day=$(echo $opsslcertexpdate | sed 's/notAfter=//' | awk '{print $2}')
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
	done
}

###Code below search certificate in local filesystem
certificateparsing pem.files
certificateparsing crt.files
