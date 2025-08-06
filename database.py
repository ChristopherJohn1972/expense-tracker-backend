import os
import json
import datetime
from flask import Flask, request, jsonify
import firebase_admin
from firebase_admin import credentials, firestore, auth

# Initialize Flask app
app = Flask(__name__)

# Initialize Firebase
service_account_info = json.loads(os.environ['FIREBASE_SERVICE_ACCOUNT'])
cred = credentials.Certificate(service_account_info)
firebase_admin.initialize_app(cred)
db = firestore.client()

# Frontend URL for CORS
FRONTEND_URL = "https://christopherjohn1972.github.io"

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = FRONTEND_URL
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

# Verify Firebase token
def verify_token(id_token):
    try:
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token['uid']
    except Exception as e:
        print(f"Token verification failed: {str(e)}")
        return None

# API Endpoints
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    try:
        user = auth.create_user(email=email, password=password)
        user_ref = db.collection('users').document(user.uid)
        user_ref.set({
            'email': email,
            'wallets': [],
            'created_at': datetime.datetime.now(datetime.timezone.utc),
            'currency': 'USD'
        })
        return jsonify({'uid': user.uid, 'email': email}), 201
    except auth.EmailAlreadyExistsError:
        return jsonify({'error': 'Email already exists'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    try:
        user = auth.get_user_by_email(email)
        return jsonify({'uid': user.uid, 'email': email}), 200
    except auth.UserNotFoundError:
        return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/wallet', methods=['POST'])
def create_wallet():
    id_token = request.headers.get('Authorization')
    if not id_token: return jsonify({'error': 'Unauthorized'}), 401

    uid = verify_token(id_token)
    if not uid: return jsonify({'error': 'Invalid token'}), 401

    wallet_name = request.json.get('name')
    wallet_ref = db.collection('wallets').document()
    wallet_id = wallet_ref.id

    wallet_ref.set({
        'name': wallet_name,
        'creator': uid,
        'members': [uid],
        'balance': 0.0,
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    })

    db.collection('users').document(uid).update({
        'wallets': firestore.ArrayUnion([wallet_id])
    })

    return jsonify({'wallet_id': wallet_id, 'name': wallet_name}), 201

@app.route('/wallet/<wallet_id>/expense', methods=['POST'])
def add_expense(wallet_id):
    id_token = request.headers.get('Authorization')
    if not id_token: return jsonify({'error': 'Unauthorized'}), 401

    uid = verify_token(id_token)
    if not uid: return jsonify({'error': 'Invalid token'}), 401

    data = request.json
    wallet_ref = db.collection('wallets').document(wallet_id)
    wallet = wallet_ref.get()

    if not wallet.exists: return jsonify({'error': 'Wallet not found'}), 404
    if uid not in wallet.to_dict().get('members', []): return jsonify({'error': 'Forbidden'}), 403

    expense_ref = wallet_ref.collection('expenses').document()
    expense_ref.set({
        'amount': data.get('amount'),
        'category': data.get('category'),
        'date': datetime.datetime.now(datetime.timezone.utc),
        'receipt_url': data.get('receipt_url'),
        'added_by': uid
    })

    wallet_ref.update({'balance': firestore.Increment(data.get('amount'))})
    return jsonify({'expense_id': expense_ref.id}), 201

@app.route('/wallet/<wallet_id>/expenses', methods=['GET'])
def get_expenses(wallet_id):
    id_token = request.headers.get('Authorization')
    if not id_token: return jsonify({'error': 'Unauthorized'}), 401

    uid = verify_token(id_token)
    if not uid: return jsonify({'error': 'Invalid token'}), 401

    wallet_ref = db.collection('wallets').document(wallet_id)
    wallet = wallet_ref.get()

    if not wallet.exists: return jsonify({'error': 'Wallet not found'}), 404
    if uid not in wallet.to_dict().get('members', []): return jsonify({'error': 'Forbidden'}), 403

    expenses = []
    for expense in wallet_ref.collection('expenses').order_by('date', direction=firestore.Query.DESCENDING).stream():
        exp_data = expense.to_dict()
        exp_data['id'] = expense.id
        exp_data['date'] = exp_data['date'].isoformat()
        expenses.append(exp_data)

    return jsonify({
        'wallet_id': wallet_id,
        'wallet_name': wallet.to_dict().get('name'),
        'balance': wallet.to_dict().get('balance', 0),
        'expenses': expenses
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)# Write your code here :-)
