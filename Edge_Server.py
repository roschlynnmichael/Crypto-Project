from flask import Flask, render_template, request, jsonify, send_file, abort
from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.toolbox.conversion import *
from charm.schemes.abenc.abenc_lsw08 import KPabe
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from charm.core.engine.util import objectToBytes, bytesToObject
import requests
import os
import hashlib
import sys
import pytesseract
from PIL import Image
import io
import base64
import datetime
import traceback

app = Flask(__name__)

AIA_URL = "https://localhost:5000/edge_registration"
EDGE_IDENTITY = "Image to Text Recognition Server"
SERVICE_ID = "OCR"

# KPABE Configuration
group = PairingGroup('SS1024')
kpabe = KPabe(group)

def deserialize_secret_key(serialized_key):
    try:
        byte_key = base64.b64decode(serialized_key)
        secret_key = bytesToObject(byte_key, group)
        return secret_key
    except Exception as e:
        raise ValueError(f"Failed to deserialize secret key: {str(e)}")

def local_only(f):
    def decorated_function(*args, **kwargs):
        if request.remote_addr not in ['127.0.0.1', '::1']:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register_edge', methods = ['POST'])
@local_only
def begin_registration():
    global SECRET_KEY_OCR #checks
    data = {
            "edge_identity": EDGE_IDENTITY,
            "edge_service_id": SERVICE_ID
    }
    response = requests.post(AIA_URL, headers={'Content-Type': 'application/json'}, json=data, verify=False)
    if response.status_code == 200:
        SECRET_KEY_SERIALIZED = response.json().get('secret_key_edge')
        if SECRET_KEY_SERIALIZED is None:
            return jsonify({"error": "Secret key not received from AIA"}), 500
        SECRET_KEY_OCR = deserialize_secret_key(SECRET_KEY_SERIALIZED)
        return jsonify({"message": "Successfully registered with AIA"}), 200
    else:
        return jsonify({"error": "Failed to register with AIA"}), response.status_code

def deserialize_ciphertext(serialized_ciphertext):
    try:
        serialized_c2 = base64.b64decode(serialized_ciphertext)
        cipher_c2 = bytesToObject(serialized_c2, group)
        return cipher_c2
    except Exception as e:
        raise ValueError(f"Failed to deserialize ciphertext: {str(e)}")

def decrypt_aes_key(ciphertext_c2):
    plaintext = kpabe.decrypt(ciphertext_c2, SECRET_KEY_OCR)
    nonhash_aes_key = objectToBytes(plaintext, group)
    hash_aes_key = hashlib.sha256(nonhash_aes_key).digest()
    return hash_aes_key

def decrypt_data(ciphertext_c1, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ciphertext_c1) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data

@app.route('/decrypt', methods=['POST'])
def decrypt_and_process():
    if SECRET_KEY_OCR is None:
        return jsonify({"Error": "Edge not registered"}), 502
    #print(SECRET_KEY_SMB)
    data = request.get_json()
    ciphertext_c1 = bytes.fromhex(data['c1'])
    #print(ciphertext_c1)
    serialized_ciphertext_c2 = data['c2']
    #print(serialized_ciphertext_c2)
    aes_iv = bytes.fromhex(data['iv'])
    #print(aes_iv)
    try:
        deserialized_ciphertext_c2 = deserialize_ciphertext(serialized_ciphertext_c2)
        #print(deserialized_ciphertext_c2)
        aes_key = decrypt_aes_key(deserialized_ciphertext_c2)
        #print("Decrypted AES Key:", aes_key)
    except Exception as e:
        #print("Error during AES key decryption:", str(e))
        return jsonify({'Error': 'Failed to decrypt AES key', 'Details': str(e)}), 501
    try:
        decrypted_image_data = decrypt_data(ciphertext_c1, aes_key, aes_iv)
        image = Image.open(io.BytesIO(decrypted_image_data))
        ocr_result = pytesseract.image_to_string(image)
        file_path = '/home/roschlynn/files/OCR_Results/ocr_result.txt'
        with open(file_path, 'w') as file:
            file.write(ocr_result)
        return jsonify({'OCR_Result': ocr_result})
    except Exception as e:
        print("Error during image decryption or OCR:", str(e))
        return jsonify({'Error': 'Failed during image decryption or OCR', 'Details': str(e)}), 500

SECRET_KEY_OCR = None
if __name__ == "__main__":
    with app.test_client() as client:
        client.post('/register_edge')
    app.run(host='0.0.0.0', port=8000, debug=True, ssl_context=('/home/roschlynn/ssl_keys/cert.pem', '/home/roschlynn/ssl_keys/key.pem'))