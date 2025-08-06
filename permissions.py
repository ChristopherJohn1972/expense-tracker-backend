from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from crud import load_data, save_data, create_expense_entry, get_user_expenses
import csv
import uuid

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Simulated Database
class SimulatedDB:
    def __init__(self):
        self.users = {}
        self.wallets = {}
        self.user_wallets = {}
        self.expenses = {}
        self.categories = ['Food & Dining', 'Shopping', 'Transportation', 'Entertainment', 'Utilities', 'Healthcare', 'Travel', 'Education', 'Other']

    # User methods
    def add_user(self, username, email, password):
        user_id = str(uuid.uuid4())
        self.users[user_id] = {
            'id': user_id,
            'username': username,
            'email': email,
            'password': generate_password_hash(password),
            'created_at': datetime.now()
        }
        return user_id

    def get_user(self, user_id):
        return self.users.get(user_id)

    def get_user_by_username(self, username):
        for user in self.users.values():
            if user['username'] == username:
                return user
        return None

    # Wallet methods
    def add_wallet(self, name, description, created_by):
        wallet_id = str(uuid.uuid4())
        self.wallets[wallet_id] = {
            'id': wallet_id,
            'name': name,
            'description': description,
            'created_by': created_by,
            'created_at': datetime.now()
        }

        # Add creator as admin
        self.add_user_to_wallet(wallet_id, created_by, 'admin')

        return wallet_id

    def get_wallet(self, wallet_id):
        return self.wallets.get(wallet_id)

    def get_user_wallets(self, user_id):
        user_wallet_ids = [uw['wallet_id'] for uw in self.user_wallets.values()
                          if uw['user_id'] == user_id]
        return [self.wallets[wid] for wid in user_wallet_ids if wid in self.wallets]

    # UserWallet methods
    def add_user_to_wallet(self, wallet_id, user_id, role='member'):
        uw_id = str(uuid.uuid4())
        self.user_wallets[uw_id] = {
            'id': uw_id,
            'user_id': user_id,
            'wallet_id': wallet_id,
            'role': role
        }

    def get_user_wallet_role(self, user_id, wallet_id):
        for uw in self.user_wallets.values():
            if uw['user_id'] == user_id and uw['wallet_id'] == wallet_id:
                return uw['role']
        return None

    def get_wallet_members(self, wallet_id):
        member_ids = [uw['user_id'] for uw in self.user_wallets.values()
                     if uw['wallet_id'] == wallet_id]
        return [self.users[uid] for uid in member_ids if uid in self.users]

    def remove_user_from_wallet(self, wallet_id, user_id):
        to_remove = []
        for uw_id, uw in self.user_wallets.items():
            if uw['user_id'] == user_id and uw['wallet_id'] == wallet_id:
                to_remove.append(uw_id)

        for uw_id in to_remove:
            del self.user_wallets[uw_id]

    # Expense methods
    def add_expense(self, amount, description, category, user_id, wallet_id):
        expense_id = str(uuid.uuid4())
        self.expenses[expense_id] = {
            'id': expense_id,
            'amount': float(amount),
            'description': description,
            'category': category,
            'user_id': user_id,
            'wallet_id': wallet_id,
            'date': datetime.now()
        }
        return expense_id

    def get_wallet_expenses(self, wallet_id):
        return [exp for exp in self.expenses.values() if exp['wallet_id'] == wallet_id]

    def delete_expense(self, expense_id):
        if expense_id in self.expenses:
            del self.expenses[expense_id]
            return True
        return False

# Create simulated database
db = SimulatedDB()

# Helper Functions
def get_current_user():
    if 'user_id' in session:
        return db.get_user(session['user_id'])
    return None

def has_wallet_permission(wallet_id, min_role='member'):
    user = get_current_user()
    if not user:
        return False

    # Check if user is the wallet creator
    wallet = db.get_wallet(wallet_id)
    if wallet and wallet['created_by'] == user['id']:
        return True

    # Check user's role in the wallet
    user_role = db.get_user_wallet_role(user['id'], wallet_id)

    if not user_role:
        return False

    # Check role permissions
    roles = {'member': 1, 'admin': 2}
    return roles.get(user_role, 0) >= roles.get(min_role, 1)

# Routes
@app.route('/')
def index():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    wallets = db.get_user_wallets(user['id'])

    # Calculate totals for each wallet
    for wallet in wallets:
        expenses = db.get_wallet_expenses(wallet['id'])
        wallet['total'] = sum(exp['amount'] for exp in expenses)
        wallet['expense_count'] = len(expenses)

    return render_template('index.html', user=user, wallets=wallets)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if db.get_user_by_username(username):
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        user_id = db.add_user(username, email, password)
        session['user_id'] = user_id
        flash('Account created successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = db.get_user_by_username(username)

        if not user or not check_password_hash(user['password'], password):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))

        session['user_id'] = user['id']
        flash('Logged in successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

@app.route('/create_wallet', methods=['GET', 'POST'])
def create_wallet():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']

        wallet_id = db.add_wallet(name, description, user['id'])
        flash('Wallet created successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('create_wallet.html')

@app.route('/wallet/<wallet_id>')
def wallet_details(wallet_id):
    if not has_wallet_permission(wallet_id):
        flash('You do not have permission to access this wallet', 'danger')
        return redirect(url_for('index'))

    wallet = db.get_wallet(wallet_id)
    if not wallet:
        flash('Wallet not found', 'danger')
        return redirect(url_for('index'))

    expenses = db.get_wallet_expenses(wallet_id)
    members = db.get_wallet_members(wallet_id)

    # Calculate total expenses
    total_expenses = sum(exp['amount'] for exp in expenses)

    # Get current user role in this wallet
    current_user = get_current_user()
    user_role = db.get_user_wallet_role(current_user['id'], wallet_id)

    # Get creator user
    creator = db.get_user(wallet['created_by'])

    return render_template(
        'wallet_details.html',
        wallet=wallet,
        expenses=expenses,
        members=members,
        total_expenses=total_expenses,
        user_role=user_role,
        creator=creator
    )

@app.route('/add_expense/<wallet_id>', methods=['GET', 'POST'])
def add_expense(wallet_id):
    if not has_wallet_permission(wallet_id):
        flash('You do not have permission to add expenses to this wallet', 'danger')
        return redirect(url_for('index'))

    wallet = db.get_wallet(wallet_id)
    if not wallet:
        flash('Wallet not found', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        amount = request.form['amount']
        description = request.form['description']
        category = request.form['category']

        db.add_expense(amount, description, category, session['user_id'], wallet_id)
        flash('Expense added successfully!', 'success')
        return redirect(url_for('wallet_details', wallet_id=wallet_id))

    return render_template('add_expense.html', wallet=wallet, categories=db.categories)

@app.route('/manage_members/<wallet_id>', methods=['GET', 'POST'])
def manage_members(wallet_id):
    if not has_wallet_permission(wallet_id, 'admin'):
        flash('You do not have permission to manage this wallet', 'danger')
        return redirect(url_for('index'))

    wallet = db.get_wallet(wallet_id)
    if not wallet:
        flash('Wallet not found', 'danger')
        return redirect(url_for('index'))

    members = db.get_wallet_members(wallet_id)

    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']

        user = db.get_user_by_username(username)
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('manage_members', wallet_id=wallet_id))

        # Check if user is already a member
        existing_role = db.get_user_wallet_role(user['id'], wallet_id)
        if existing_role:
            flash('User is already a member of this wallet', 'warning')
            return redirect(url_for('manage_members', wallet_id=wallet_id))

        # Add user to wallet
        db.add_user_to_wallet(wallet_id, user['id'], role)
        flash(f'{username} added to wallet as {role}', 'success')
        return redirect(url_for('manage_members', wallet_id=wallet_id))

    return render_template('manage_members.html', wallet=wallet, members=members)

@app.route('/remove_member/<wallet_id>/<user_id>')
def remove_member(wallet_id, user_id):
    if not has_wallet_permission(wallet_id, 'admin'):
        flash('You do not have permission to manage this wallet', 'danger')
        return redirect(url_for('index'))

    # Cannot remove the creator
    wallet = db.get_wallet(wallet_id)
    if wallet['created_by'] == user_id:
        flash('Cannot remove the wallet creator', 'danger')
        return redirect(url_for('manage_members', wallet_id=wallet_id))

    # Remove user from wallet
    db.remove_user_from_wallet(wallet_id, user_id)
    flash('Member removed successfully', 'success')
    return redirect(url_for('manage_members', wallet_id=wallet_id))

@app.route('/delete_expense/<expense_id>')
def delete_expense(expense_id):
    expense = next((e for e in db.expenses.values() if e['id'] == expense_id), None)
    if not expense:
        flash('Expense not found', 'danger')
        return redirect(url_for('index'))

    # Only admins or the user who created the expense can delete it
    current_user = get_current_user()
    if not has_wallet_permission(expense['wallet_id'], 'admin') and expense['user_id'] != current_user['id']:
        flash('You do not have permission to delete this expense', 'danger')
        return redirect(url_for('wallet_details', wallet_id=expense['wallet_id']))

    db.delete_expense(expense_id)
    flash('Expense deleted successfully', 'success')
    return redirect(url_for('wallet_details', wallet_id=expense['wallet_id']))

if __name__ == '__main__':
    app.run(debug=True)# Write your code here :-)
