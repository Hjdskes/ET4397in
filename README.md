# Introduction

This project is written in Golang, using the regular libpcap library in
combination with gopacket. In some parts of the code, the Golang's net package
is used. The hub package is inspired by https://github.com/vtg/pubsub. To create
the test ARP pcap file, I used Scapy.

# Installation

To setup the software, you need to perform the following steps. All these steps
are automatically executed using the install.sh script as required. Note that
the script assumes the .zip file is found in ~/Downloads/ET4397IN.zip.

1. You first need to install Golang, for this I have provided a bash script as
required:

sudo add-apt-repository ppa:ubuntu-lxc/lxd-stable
sudo apt-get update
sudo apt-get install golang

2. If $GOPATH is not set, set it: export GOPATH=$HOME/go

3. Create a workspace directory, with a source directory inside it:

mkdir -p $GOPATH/src/github.com/Hjdskes
cd $GOPATH/src/github.com/Hjdskes

4. Extract the source code into this directory:

cp ~/Downloads/ET4397IN.zip .
unzip -a ET4397IN.zip
cd ET4397IN

5. Finally, install the dependencies and build and install the package from the
current directory:

go get ./...
go install

6. The program is installed into $GOPATH/bin/. You can either call it with the
full path, or add $GOPATH/bin to your PATH: export PATH=$PATH:$(go env
GOPATH)/bin and then call it by name. You need to run the program with
--device="enp0s3". See --help for the other options.

If something doesn't work, please do send me an email!

# Configuration

The configuration file is found in config.json, and unsurprisingly uses the JSON
format. Currently, the modules support the following configuration:

* ARP module: a JSON object called `arp-bindings`, which contains arrays named
  by IP addresses to the MAC addresses they are allowed to bind to. Example:
  ```
       "arp-bindings":
       {
               "192.168.0.1":
               [
                       "aa:bb:cc:dd:ee:ff"
               ],
               "192.168.0.2":
               [
                       "aa:aa:aa:aa:aa:aa",
                       "bb:bb:bb:bb:bb:bb"
               ]
       }
  ```
* WiFi module: a JSON number called `interval`, containing the interval in
  nanoseconds within which two dissasociation or deauthentication frames or two
  ARP requests are considered to be an attack. Example: `"interval":
  1000000000`.
* DoS module:
  * A JSON number called `syn-interval`, containing the interval in milliseconds
    after which the current count of SYNs is reset. Example: `"syn-interval":
    1000`.
  * A JSON number called `syn-threshold`, containing the SYN packet threshold
    which when crossed signals a SYN flood attack. Example: `"syn-treshold": 2`.
  * A string called `forward-ip`, containing the IP address to which to forward
    packets. Example: `"forward-ip": "127.0.0.1"`.

If no configuration file is given, or the configuration file is not complete,
sane defaults are applied:

* ARP module: all IP to MAC bindings are considered valid.
* WiFi module: a default interval of 1 second (1000000000 nanoseconds) is used.
* DoS module: a default interval of 1 second (1000 milliseconds) is used,
  with a default threshold of 1 packets and a forwarding address of
  "127.0.0.1"
