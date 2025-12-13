#!/bin/bash

install-sezyo-v2() {
	if ! command -v aws; then
		curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
		unzip awscliv2.zip
		sudo ./aws/install
        	rm -rf awscliv2.zip
	fi
	if ! command -v go version; then
	    wget https://golang.org/dl/go1.17.1.linux-amd64.tar.gz && rm -rf /usr/local/go && tar -C /usr/local -xzf go1.17.1.linux-amd64.tar.gz
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
	fi
	sudo apt-get update && sudo apt-get install curl jq git python3-pip -y
	pip3 install git-dumper
	GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx
}
install-sezyo-v2
source ~/.bashrc
