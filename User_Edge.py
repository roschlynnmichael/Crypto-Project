from flask import Flask, render_template, request, jsonify, session
from charm.toolbox.pairinggroup import PairingGroup, serialize, deserialize, GT
from charm.schemes.abenc.abenc_lsw08 import KPabe
from charm.toolbox.conversion import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from charm.core.engine.util import objectToBytes, bytesToObject
from cryptography.hazmat.backends import default_backend
import requests
import os
import base64
import hashlib

WEB_SERVER_URL = 'http://127.0.0.1:8000/decrypt'
AIA_URL = 'https://127.0.0.1:5000/user_registration'
app = Flask(__name__)
app.config.from_pyfile('config.cfg')
app.secret_key = app.config['SECRET_KEY']

user_details = {}

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

group = PairingGroup('SS1024')
kpabe = KPabe(group)

def deserialize_public_key(serialized_key):
    try:
        byte_key = base64.b64decode(serialized_key)
        public_key = bytesToObject(byte_key, group)
        return public_key
    except Exception as e:
        raise ValueError(f"Failed to deserialize public key: {str(e)}")

def serialize_ciphertexts(ciphertext):
    try:
        cipher_bytes = objectToBytes(ciphertext, group)
        encoded_cipher = base64.b64encode(cipher_bytes).decode('utf-8')
        return encoded_cipher
    except Exception as e:
        raise ValueError(f"Failed to serialize ciphertext: {str(e)}")

def generate_ciphertext_c1(file_path):
    random_key_element = group.random(GT)
    nonhash_aes_key = objectToBytes(random_key_element, group)
    hash_aes_key = hashlib.sha256(nonhash_aes_key).digest()
    iv = os.urandom(16)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(hash_aes_key), modes.CBC(iv), backend = backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    ciphertext = b''
    with open(file_path, 'rb') as file:
        while True:
            file_data = file.read(1024)
            if not file_data:
                break
            padded_data = padder.update(file_data)
            ciphertext += encryptor.update(padded_data)
    padded_data = padder.finalize()
    ciphertext += encryptor.update(padded_data)
    ciphertext += encryptor.finalize()
    return ciphertext, random_key_element, iv

def generate_ciphertext_c2_c3(serialized_public_key, aes_key):
    attributes = session.get('ATTRIBUTES', [])
    deserialized_public_key = deserialize_public_key(serialized_public_key)
    ciphertext_aes_Key = kpabe.encrypt(deserialized_public_key, aes_key, attributes)
    return ciphertext_aes_Key

def generate_ciphertexts(file_path, serialized_public_key):
    ciphertext_c1, random_key_element, aes_iv = generate_ciphertext_c1(file_path)
    ciphertext_c2 = generate_ciphertext_c2_c3(serialized_public_key, random_key_element)
    return ciphertext_c1, ciphertext_c2, aes_iv

@app.route('/upload-file')
def upload_file():
    return render_template('upload_file.html')

@app.route('/upload', methods = ['GET', 'POST'])
def upload_and_encrypt():
    if 'file' not in request.files:
        return 'No File part in this request'
    file = request.files['file']
    if file.filename == '':
        return 'No File Selected'
    if file:
        file_path = os.path.join('/home/roschlynn/files', file.filename)
        file.save(file_path)
        try:
            c1, c2, iv = generate_ciphertexts(file_path, session.get('PUBLIC_KEY'))
            data = {
            'c1': c1.hex(),
            'c2': serialize_ciphertexts(c2),
            'iv': iv.hex(),
            'attributes': session.get('ATTRIBUTES', [])
            }
            response = requests.post(WEB_SERVER_URL, json = data)
            data = response.json()
            ocr_result = data['OCR_Result']
            if response.status_code == 200:
                return jsonify({'message': 'Ciphertexts and IV sent to Edge! OCR Successful!', 'ocr_result': ocr_result})
            else:
                return jsonify({'error': 'Failure occurred! Not able to send!'}), response.status_code
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'Failed upload'}), 500

@app.route('/user_registration', methods=['POST'])
def begin_user_registration():
    data = request.get_json()
    required_fields = ['email', 'name', 'identification', 'password', 'service_request']
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Missing required fields"}), 400

    email = data['email']
    name = data['name']
    identification = data['identification']
    password = data['password']
    service_request = data['service_request']
    password_hash = hash_password(password)
    registration_data = {
        "email": email, 
        "name": name, 
        "identification": identification,
        "service_request": service_request,
        "password_hash": password_hash
    }
    response = requests.post(AIA_URL, headers={'Content-Type': 'application/json'}, json=registration_data, verify=False)
    if response.status_code == 200:
        response_data = response.json()
        user_details[email] = {
            "name": name,
            "identification": identification,
            "service_request": service_request,
            "attribute": response_data.get('user_attribute_generated'),
            "master_public_key": response_data.get('master_public_key')
        }
        session['ATTRIBUTES'] = response_data.get('user_attribute_generated', '').split(',') if response_data.get('user_attribute_generated') else []
        session['PUBLIC_KEY'] = response_data.get('master_public_key')
        return jsonify({"message": "Registration Successful", "user_details": user_details[email]})
    else:
        return jsonify({"message": "Registration Failed"}), response.status_code

@app.route('/')
def home():
    return render_template('user_registration.html')

if __name__ == "__main__":
    app.run(host = '0.0.0.0', port = 8001, debug = True)

