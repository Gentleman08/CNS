from flask import Flask, render_template, request, send_file
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
SIGNATURE_FOLDER = 'signatures'
KEYS_FOLDER = 'keys'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SIGNATURE_FOLDER'] = SIGNATURE_FOLDER
app.config['KEYS_FOLDER'] = KEYS_FOLDER

# Ensure directories exist
for folder in [UPLOAD_FOLDER, SIGNATURE_FOLDER, KEYS_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# Generate RSA key pair
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open(os.path.join(KEYS_FOLDER, 'private.pem'), 'wb') as priv_file:
        priv_file.write(private_key)
    with open(os.path.join(KEYS_FOLDER, 'public.pem'), 'wb') as pub_file:
        pub_file.write(public_key)

generate_keys()  # Generate keys at startup

# Sign a document
def sign_document(file_path):
    with open(file_path, 'rb') as file:
        document = file.read()
    with open(os.path.join(KEYS_FOLDER, 'private.pem'), 'rb') as key_file:
        private_key = RSA.import_key(key_file.read())
    
    digest = SHA256.new(document)
    signature = pkcs1_15.new(private_key).sign(digest)
    
    signature_path = os.path.join(SIGNATURE_FOLDER, 'signature.sig')
    with open(signature_path, 'wb') as sig_file:
        sig_file.write(signature)
    return signature_path

# Verify a signature
def verify_signature(file_path, signature_path):
    with open(file_path, 'rb') as file:
        document = file.read()
    with open(signature_path, 'rb') as sig_file:
        signature = sig_file.read()
    with open(os.path.join(KEYS_FOLDER, 'public.pem'), 'rb') as key_file:
        public_key = RSA.import_key(key_file.read())
    
    digest = SHA256.new(document)
    try:
        pkcs1_15.new(public_key).verify(digest, signature)
        return "Verification successful: Document is authentic."
    except ValueError:
        return "Verification failed: Document is altered or incorrect key used."

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/sign', methods=['POST'])
def sign():
    if 'file' not in request.files:
        return "No file uploaded"
    file = request.files['file']
    if file.filename == '':
        return "No file selected"
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)
    signature_path = sign_document(file_path)
    return send_file(signature_path, as_attachment=True)

@app.route('/verify', methods=['POST'])
def verify():
    if 'file' not in request.files or 'signature' not in request.files:
        return "File and signature required"
    file = request.files['file']
    signature = request.files['signature']
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    signature_path = os.path.join(SIGNATURE_FOLDER, 'uploaded_signature.sig')
    file.save(file_path)
    signature.save(signature_path)
    result = verify_signature(file_path, signature_path)
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
