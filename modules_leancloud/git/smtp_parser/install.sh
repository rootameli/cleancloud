#!/bin/bash

sudo apt-get update && sudo apt-get upgrade -y
curl -sL https://deb.nodesource.com/setup_14.x -o nodesource_setup.sh
chmod +x nodesource_setup.sh
./nodesource_setup.sh
sudo npm install -g yarn
cd src/
yarn
