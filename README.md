# Key Policy Attribute Based Encryption using Charm Crypto and Python Flask
Built and Developed by Saint Louis University as a semester long class project for the course of CSCI-5930 Applied Cryptography under the guidance of Prof. Reza Tourani.

### Installation
Use the ```install.sh``` script in the Install Script Folder to automatically update, upgrade, download, build and compile the necessary packages required.

### Generate your own OpenSSL RSA Keys to use with the system
Use this command to generate your own OpenSSL RSA keys to be able to use TLS (Transport Layer Security) connection.
```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```
The python flask server will ask for passphrase for the key. Remove the passphrase by running the following command
```
cd <to_key_cert_directory>
openssl rsa -in key.pem -out newkey.pem
```
Once the key and certificate for TLS Connection is generated, go to every individual .py file and add the path to the key and certificate there.

### Starting up the servers.
1. Start AIA.py file first. The Attribute Issuing Authority needs to be alive first before any KP-ABE encryptions and decryptions are done.
```
python3 AIA.py
```
2. Start the Edge_Server.py file. The registration of the Edge Server takes place automatically at startup. Be sure to run the AIA.py file first.
```
python3 Edge_Server.py
```
3. Then start the User_Edge.py and register with the following details on the HTML page it displays. This is to generate the attributes for the user.
```
python3 User_Edge.py
```
4. Once all the above three steps are done, proceed to the OCR Upload page. The implemented service is image to text using Google's Tesseract OCR.
5. Output will be given as a downloadable txt file.

#### Known Bug
Install Script is buggy and fails at installation of GMP (should be fixed in the future).

### Implemented by referring to the following paper
https://scholar.google.com/citations?view_op=view_citation&hl=en&user=Z1KsnyIAAAAJ&citation_for_view=Z1KsnyIAAAAJ:7PzlFSSx8tAC

Dougherty, S., Tourani, R., Panwar, G., Vishwanathan, R., Misra, S., & Srikanteswara, S. (2021). APECS: A distributed access control framework for pervasive edge computing services. In Proceedings of the 2021 ACM SIGSAC Conference on Computer and Communications Security (pp. 1405-1420).