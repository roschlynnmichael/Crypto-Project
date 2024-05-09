#!/bin/bash

echo "Charm Crypto Installation"
echo "Beginning install of Charm Crypto"
mkdir packages
cd packages

#Update all packages
sudo apt-get update
sudo apt-get upgrade -y

#Install GCC Make Perl
sudo apt-get install gcc make perl -y

#Install M4 Flex Bison
sudo apt-get install m4 flex bison -y

#Install Python Dependency Packages
sudo apt-get install python3-setuptools python3-dev libssl-dev python3-pip -y

#Install PyParsing
pip3 install pyparsing==2.4.6

#Compile and Install OpenSSL
wget https://www.openssl.org/source/old/1.0.0/openssl-1.0.0s.tar.gz
sudo tar -xzvf openssl-1.0.0s.tar.gz -C /usr/local/src
cd /usr/local/src/openssl-1.0.0s/
sudo ./config shared --prefix=/usr/local/openssl --openssldir=/usr/lib/openssl
sudo make
sudo make install
sudo mv /usr/bin/openssl /usr/bin/openssl.bak
sudo ln -s /usr/local/openssl/bin/openssl /usr/bin/openssl
sudo ln -s /usr/local/openssl/include/openssl /usr/include/openssl
sudo ln -s /usr/local/openssl/lib/libssl.so.1.0.0 /usr/lib/libssl.so
sudo ln -s /usr/local/openssl/lib/libcrypto.so.1.0.0 /usr/lib/libcrypto.so
echo "Test OpenSSL Version Now!"
sleep 3
openssl version
sleep 3

cd ~
cd packages

#Compile and Install GMP
wget https://gmplib.org/download/gmp/gmp-5.1.3.tar.bz2
sudo tar -jxvf gmp_5.1.3.tar.bz2 -C /usr/local/src
cd /usr/local/src/gmp-5.1.3
sudo ./configure
sudo make
sudo make install

cd ~
cd packages

#Compile and Install PBC
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
sudo tar -zxvf pbc-0.5.14.tar.gz -C /usr/local/src/
cd /usr/local/src/pbc-0.5.14/
sudo ./configure
sudo make
sudo make install

cd ~
cd packages

#Compile and Install Charm Crypto
sudo apt-get install git curl -y
git clone https://github.com/JHUISI/charm.git
sudo mv ./charm /usr/local/src
cd /usr/local/src/charm
sudo ./configure.sh
sudo make
sudo make install

#Script only works on Windows Subsystem for Linux V2