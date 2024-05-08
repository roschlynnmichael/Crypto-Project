import hashlib
import re
import base64
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, abort
from charm.toolbox.pairinggroup import PairingGroup, GT, serialize, deserialize
from charm.schemes.abenc.abenc_lsw08 import KPabe
from charm.core.engine.util import objectToBytes, bytesToObject
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

#Begin Flask App
app = Flask(__name__)
app.config.from_pyfile('config.cfg')
app.secret_key = app.config['SECRET_KEY']
PREDEFINED_HASH = app.config['PREDEFINED_HASH']

#Basic Crypto Setup Required
group = PairingGroup('SS1024')
kpabe = KPabe(group)
(master_public_key, master_key) = kpabe.setup()

#Flask Login for AIA
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, email, password_hash):
        self.id = id
        self.email = email
        self.password_hash = password_hash

users = {"1": User(1, "roschlynn@outlook.com", generate_password_hash("dsouza5451"))}
print(f"Initial users: {[u.email for u in users.values()]}")

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

#Store attributes and access policies for every user in dictionary
#Also store users and their assigned attributes and policies in dictionary
policies = {}
users_registered = {}
edges_registered = {}

def serialize_public_key(public_key):
    try:
        pk_bytes = objectToBytes(public_key, group)
        encoded_key = base64.b64encode(pk_bytes).decode('utf-8')
        return encoded_key
    except Exception as e:
        raise ValueError(f"Failed to serialize public key: {str(e)}")

def serialize_secret_key(secret_key):
    try:
        sk_bytes = objectToBytes(secret_key, group)
        encoded_key = base64.b64encode(sk_bytes).decode('utf-8')
        return encoded_key
    except Exception as e:
        raise ValueError(f"Failed to serialize secret key: {str(e)}")

def generate_secret_key(master_public_key, master_key, policy):
    secret_key = kpabe.keygen(master_public_key, master_key, policy)
    return secret_key

@app.route('/user_registration', methods=['POST'])
def register_user():
    data = request.get_json()
    if not data or 'email' not in data or 'name' not in data or 'identification' not in data or 'password_hash' not in data or 'service_request' not in data:
        return jsonify({"error": "Missing user email or name or identification or password hash or service request"}), 400
    else:
        email = data['email']
        name = data['name']
        service_request = data['service_request']
        password_hash = data['password_hash']
        if password_hash == PREDEFINED_HASH:
            service_id_found = None
            for edge_identity, service_id in edges_registered.items():
                if service_request in service_id:
                    edge_identity_found = edge_identity
                    service_id_found = service_request
                    break
            if service_id_found:
                if email in users_registered:
                    if service_id_found in users_registered[email].get("attributes", []):
                        return jsonify({"note": "User already has this attribute"}), 200
                    else:
                        existing_services = users_registered[email].get("service_requests", [])
                        existing_attributes = users_registered[email].get("attributes", [])
                        existing_services.append(edge_identity_found)
                        existing_attributes.append(service_id_found)
                        users_registered[email]["service_requests"] = existing_services
                        users_registered[email]["attributes"] = existing_attributes
                else:
                    users_registered[email] = {"name": name, "service_request": edge_identity_found, "attribute": service_id_found}
                    serialized_master_public_key = serialize_public_key(master_public_key)
                return jsonify({"user_attribute_generated": service_id_found, "requested_service": edge_identity_found, "master_public_key": serialized_master_public_key}), 200
            else:
                return jsonify({"error": "Service request not registered or unavailable"}), 400
        else:
            abort(401)

@app.route('/edge_registration', methods=['POST'])
def register_edge():
    data = request.get_json()
    if not data or 'edge_identity' not in data or 'edge_service_id' not in data:
        return jsonify({"error": "Missing edge identity or edge service id"}), 400
    else:
        edge_identity = data['edge_identity']
        edge_service_id = data['edge_service_id']
        if edge_identity in edges_registered:
            if edge_service_id in edges_registered[edge_identity]:
                return jsonify({"note": "Edge identity and edge service id already registered"}), 200
            else:
                edges_registered[edge_identity].append(edge_service_id)
                end_policy_edge = '(PYT or OCR)'
                try:
                    secret_key_edge = generate_secret_key(master_public_key, master_key, end_policy_edge)
                    return jsonify({"secret_key_edge": str(secret_key_edge)}), 200
                except Exception as e:
                    return jsonify({"error": "Error generating secret key: {}".format(str(e))}), 500
        else:
            edges_registered[edge_identity] = [edge_service_id]
            enc_policy_edge = '(PYT or OCR)'
            try:
                secret_key_edge = generate_secret_key(master_public_key, master_key, enc_policy_edge)
                return jsonify({"secret_key_edge": serialize_secret_key(secret_key_edge)}), 200
            except Exception as e:
                return jsonify({"error": "Error generating secret key: {}".format(str(e))}), 500
        

@app.route('/define_policies', methods = ['POST'])
def self_registration_policy():
    data = request.get_json()
    if not data or 'policyName' not in data or 'policyValue' not in data:
        return jsonify({"error": "Missing policy name or policy value or both"}), 400
    else:
        policyName = data['policyName']
        policyValue = data['policyValue']
        if policyName in policies and policies[policyName] == policyValue:
            return jsonify({"note": "Policy name and policy value already defined"}), 200
        else:
            policies[policyName] = policyValue
            return jsonify({"message": "Policy successfully defined"}), 200

@app.route('/')
@login_required
def home():
    return render_template('AIA_Registration.html', policies = policies, users_registered = users_registered, edges_registered = edges_registered)

@app.route('/login', methods=['GET', 'POST'])
def login():
    print(f"Available users: {[u.email for u in users.values()]}")  # Debug print to see available emails
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        print(email)
        print(password)
        user = next((u for u in users.values() if u.email == email), None)
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password')
            return render_template('login.html')
    return render_template('login.html')
    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/protected')
@login_required
def protected():
    return 'Logged in as: ' + current_user.email

if __name__ == "__main__":
    app.run(host = '0.0.0.0', port = 5000, debug=True, ssl_context=('/home/roschlynn/ssl_keys/cert.pem', '/home/roschlynn/ssl_keys/key.pem'))

#Generate OpenSSL Keys
#openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
