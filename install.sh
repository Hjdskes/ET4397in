#!/usr/bin/env bash

sudo add-apt-repository ppa:ubuntu-lxc/lxd-stable
sudo apt-get update
sudo apt-get install golang

export GOPATH=$HOME/go
mkdir -p $GOPATH/src/github.com/Hjdskes
cd $GOPATH/src/github.com/Hjdskes

cp ~/Downloads/ET4397IN.zip .
unzip -a ET4397IN.zip
cd ET4397IN
go get ./...
go install

