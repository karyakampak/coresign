from flask import Flask, request, jsonify
# from flask_sqlalchemy import SQLAlchemy
import os
import socket
import ctypes
import time
import datetime
import base64
import binascii

# Load the .dylib file
lib = ctypes.CDLL('/home/library/libcoresign.so')

# Define the argument types and return type of the function
lib.genCSR.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p
]
lib.genCSR.restype = ctypes.c_int

# Define the argument types and return type of the function
lib.signCSR.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
    ctypes.c_char_p, ctypes.c_char_p
]
lib.signCSR.restype = ctypes.c_int

# Define the argument types and return type of the function
lib.genP12.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, 
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p
]
lib.genP12.restype = ctypes.c_int

# Define the argument and return types of the function
lib.sign.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.sign.restype = ctypes.c_char_p

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgres://user:password@localhost:5432/mydatabase')
# db = SQLAlchemy(app)

# Directory to store files
CERT_DIRECTORY = '/home/cert/'
CSR_DIRECTORY = '/home/csr/'
KEY_DIRECTORY = '/home/key/'
P12_DIRECTORY = '/home/p12/'
CA_CERT_DIRECTORY = '/home/CA_cert/'

# Ensure the directory exists
os.makedirs(CERT_DIRECTORY, exist_ok=True)
os.makedirs(CSR_DIRECTORY, exist_ok=True)
os.makedirs(KEY_DIRECTORY, exist_ok=True)
os.makedirs(P12_DIRECTORY, exist_ok=True)
os.makedirs(CA_CERT_DIRECTORY, exist_ok=True)


@app.route('/')
def index():
    hostname = socket.gethostname()
    return f'Hello from {hostname}'

@app.route('/generate-certificate', methods=['POST'])
# curl -X POST http://localhost/generate-certificate -H "Content-Type: application/json" -d '{"nik": "3317080602970004", "passphrase": "karyakampak"}'
def genkey():
    # Record start time
    start_time = time.perf_counter()

    # Get the current timestamp
    current_time = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')  # Format as 'YYYYMMDD_HHMMSS'

    # # Get data from the POST request
    data = request.json  # Assumes JSON body

    # # Extract relevant data (e.g., 'filename' and 'content')
    niky = data.get('nik', 'nik')
    passphrase = data.get('passphrase', 'passphrase')

    # Define paths and password as required by your function
    csr_file_str = f"{CSR_DIRECTORY}{current_time}.csr"
    csr_file = csr_file_str.encode('utf-8')
    private_key_user_str = f"{KEY_DIRECTORY}{current_time}.key"
    private_key_user = private_key_user_str.encode('utf-8')
    password_user = passphrase.encode('utf-8')
    ca_cert_file_str = f"{CA_CERT_DIRECTORY}ca.crt"
    ca_cert_file = ca_cert_file_str.encode('utf-8')
    private_key_ca_str = f"{CA_CERT_DIRECTORY}ca.key"
    private_key_ca = private_key_ca_str.encode('utf-8')
    password_ca = b'karyakampak'
    user_cert_file_str = f"{CERT_DIRECTORY}{current_time}.crt"
    user_cert_file = user_cert_file_str.encode('utf-8')
    certificate_chain_str = f"{CA_CERT_DIRECTORY}chain.crt"
    certificate_chain = certificate_chain_str.encode('utf-8')
    p12_file_str = f"{P12_DIRECTORY}{current_time}.p12"
    p12_file = p12_file_str.encode('utf-8')

    # Call the function
    result = lib.genCSR(
        csr_file, private_key_user, password_user
    )

    if result == 0:
        print("CSR generation successful")
    else:
        print("CSR generation failed with code", result)

    # Call the function
    result2 = lib.signCSR(
        ca_cert_file, private_key_ca, password_ca,
        csr_file, user_cert_file
    )

    if result2 == 0:
        print("CSR signing successful")
    else:
        print("CSR signing failed with code", result2)

    # Call the function
    result3 = lib.genP12(
        private_key_user, user_cert_file, certificate_chain,
        password_user, password_user, p12_file
    )

    if result3 == 0:
        print("Operation successful")
    else:
        print("Operation failed with code", result3)

    # Print the result
    # print(result.decode('utf-8'))  # Convert bytes to string

    # Record end time
    end_time = time.perf_counter()

    # Calculate elapsed time
    elapsed_time = (end_time - start_time) * 1000

    return jsonify({'status': 'success'}), 201

@app.route('/sign-hash', methods=['POST'])
# curl -X POST http://localhost/sign-hash -H "Content-Type: application/json" -d '{"nik": "3317080602970004", "passphrase": "karyakampak", "hash": "pZGm1Av0IEBKARczz7exkNYsZb8LzaMrV7J32a2fFG4="}'
def sign():
    # Record start time
    start_time = time.perf_counter()

    # # Get data from the POST request
    data = request.json  # Assumes JSON body

    # # Extract relevant data (e.g., 'filename' and 'content')
    hashx = data.get('hash', 'hash')
    niky = data.get('nik', 'nik')
    passphrasez = data.get('passphrase', 'passphrase')

    # Create or update the file
    # file_path = os.path.join(FILE_DIRECTORY, filename)
    # with open(file_path, 'w') as f:
    #     f.write(content)

    # Call the function
    p12Path = b'/home/p12/user.p12'
    hash = b'pZGm1Av0IEBKARczz7exkNYsZb8LzaMrV7J32a2fFG4='
    passphrase = b'karyakampak'

    result = lib.sign(p12Path, hashx.encode('utf-8'), passphrase)
    # Convert the result (hex string) to bytes
    try:
        signature_bytes = binascii.unhexlify(result)  # Convert hex to bytes
    except binascii.Error:
        return jsonify({'status': 'error', 'message': 'Invalid hex string in result.'}), 500

    # Encode the bytes as Base64
    signature_base64 = base64.b64encode(signature_bytes).decode('utf-8')

    # Print the result
    # print(result.decode('utf-8'))  # Convert bytes to string

    # Record end time
    end_time = time.perf_counter()

    # Calculate elapsed time
    elapsed_time = (end_time - start_time) * 1000

    return jsonify({'status': 'success', 'signature': signature_base64, 'time_execution': f"{elapsed_time:.4f}"}), 201

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=91)
