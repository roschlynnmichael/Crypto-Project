#!/bin/bash

# Error handling
set -e

echo "Charm Crypto Installation"
echo "Beginning install of Charm Crypto"

# Create directory for packages
mkdir -p packages
cd packages

# Update all packages
sudo apt-get update
sudo apt-get upgrade -y

# Install necessary packages
sudo apt-get install gcc make perl m4 flex bison python3-setuptools python3-dev libssl-dev python3-pip git curl -y

# Check if OpenSSL, GMP, and PBC files exist before downloading
if [ ! -f "openssl-1.0.0s.tar.gz" ]; then
    wget https://www.openssl.org/source/old/1.0.0/openssl-1.0.0s.tar.gz
fi

if [ ! -f "gmp-6.3.0.tar.xz" ]; then
    wget https://gmplib.org/download/gmp/gmp-6.3.0.tar.xz
fi

if [ ! -f "pbc-0.5.14.tar.gz" ]; then
    wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
fi

# Extract files
sudo tar -xzvf openssl-1.0.0s.tar.gz -C /usr/local/src
sudo tar -xvf gmp-6.3.0.tar.xz -C /usr/local/src
sudo tar -zxvf pbc-0.5.14.tar.gz -C /usr/local/src/

# Compile and Install OpenSSL
cd /usr/local/src/openssl-1.0.0s/
sudo ./config shared --prefix=/usr/local/openssl --openssldir=/usr/lib/openssl
sudo make
sudo make install
sudo mv /usr/bin/openssl /usr/bin/openssl.bak
sudo ln -s /usr/local/openssl/bin/openssl /usr/bin/openssl
sudo ln -s /usr/local/openssl/include/openssl /usr/include/openssl
sudo ln -s /usr/local/openssl/lib/libssl.so.1.0.0 /usr/lib/libssl.so
sudo ln -s /usr/local/openssl/lib/libcrypto.so.1.0.0 /usr/lib/libcrypto.so

# Test OpenSSL version
echo "Testing OpenSSL Version Now!"
sleep 3
openssl version
sleep 3

# Compile and Install GMP
cd /usr/local/src/gmp-6.3.0
sudo ./configure
sudo make
sudo make install

# Compile and Install PBC
cd /usr/local/src/pbc-0.5.14/
sudo ./configure
sudo make
sudo make install

# Install Python packages
pip3 install pyparsing==2.4.6
pip3 install flask
pip3 install flask_login

# Perform ldconfig
sudo ldconfig

echo "All installation steps done successfully!"
