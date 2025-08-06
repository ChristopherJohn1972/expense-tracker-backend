from flask import Flask, request, jsonify
from auth import token_required  # importing decorator
import uuid
import csv
import os
import json

app = Flask(__name__)

DATA_FILE = 'storage.json'

# -------------------- Helpers --------------------

def load_data():
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'w') as f:
            json.dump({}, f)
    with open(DATA_FILE, 'r') as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

# -------------------- Routes --------------------

@app.route('/')
def index():
    return "✅ Expense API working. Use /expenses endpoints."

@app.route('/expenses', methods=['POST'])
@token_required
def create_expense(current_user):
    data = request.json
    expenses = load_data()

    expense_id = str(uuid.uuid4())
    expenses[expense_id] = {
        'user_id': current_user['id'],
        'name': data.get('name'),
        'amount': data.get('amount'),
        'category': data.get('category')
    }
    save_data(expenses)
    return jsonify({'message': 'Expense created', 'id': expense_id}), 201

@app.route('/expenses', methods=['GET'])
@token_required
def list_expenses(current_user):
    expenses = load_data()
    user_expenses = {eid: e for eid, e in expenses.items() if e['user_id'] == current_user['id']}
    return jsonify(user_expenses)

@app.route('/expenses/<expense_id>', methods=['PUT'])
@token_required
def update_expense(current_user, expense_id):
    expenses = load_data()
    if expense_id not in expenses or expenses[expense_id]['user_id'] != current_user['id']:
        return jsonify({'message': 'Not found'}), 404
    data = request.json
    expenses[expense_id].update(data)
    save_data(expenses)
    return jsonify({'message': 'Expense updated'})

@app.route('/expenses/<expense_id>', methods=['DELETE'])
@token_required
def delete_expense(current_user, expense_id):
    expenses = load_data()
    if expense_id not in expenses or expenses[expense_id]['user_id'] != current_user['id']:
        return jsonify({'message': 'Not found'}), 404
    del expenses[expense_id]
    save_data(expenses)
    return jsonify({'message': 'Expense deleted'})

@app.route('/expenses/upload', methods=['POST'])
@token_required
def upload_csv(current_user):
    if 'file' not in request.files:
        return jsonify({'message': 'No file uploaded'}), 400
    file = request.files['file']
    expenses = load_data()
    reader = csv.DictReader(file.stream.read().decode('utf-8').splitlines())
    count = 0
    for row in reader:
        expense_id = str(uuid.uuid4())
        expenses[expense_id] = {
            'user_id': current_user['id'],
            'name': row.get('name'),
            'amount': float(row.get('amount', 0)),
            'category': row.get('category', '')
        }
        count += 1
    save_data(expenses)
    return jsonify({'message': f'{count} expenses uploaded successfully'}), 201

# -------------------- Run --------------------
if __name__ == '__main__':
    app.run(debug=True)
