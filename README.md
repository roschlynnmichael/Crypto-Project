# Key Policy Attribute Based Encryption using Charm Crypto and Python Flask
Built and Developed by Francina Pali and Roschlynn Michael Dsouza as a semester long class project for the course of CSCI-5930 Applied Cryptography under the guidance of Prof. Reza Tourani.

## Installation
Use the install.sh script in the Install Script Folder to automatically update, upgrade, download, build and compile the necessary packages required.

## Generate your own OpenSSL RSA Keys to use with the system
Use this command to generate your own OpenSSL RSA keys to be able to use TLS (Transport Layer Security) connection.
```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```
The python flask server will ask for passphrase for the key. Remove the key by running the following command
```
cd <to_key_cert_directory>
openssl rsa -in key.pem -out newkey.pem
```