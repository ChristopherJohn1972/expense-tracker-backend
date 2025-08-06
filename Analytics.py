# Enhanced Expense Tracker with Reporting & Analytics
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid
import json
import matplotlib
matplotlib.use('Agg')  # Set the backend to Agg for non-GUI environments
import matplotlib.pyplot as plt
import io
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import time
import requests

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Simulated Database
class SimulatedDB:
    def __init__(self):
        self.users = {}
        self.wallets = {}
        self.user_wallets = {}
        self.expenses = {}
        self.categories = ['Food & Dining', 'Shopping', 'Transportation', 'Entertainment',
                          'Utilities', 'Healthcare', 'Travel', 'Education', 'Other']
        self.budget_alerts = {}
        self.webhooks = {}
        self.reports = {}

    # User methods
    def add_user(self, username, email, password):
        user_id = str(uuid.uuid4())
        self.users[user_id] = {
            'id': user_id,
            'username': username,
            'email': email,
            'password': generate_password_hash(password),
            'created_at': datetime.now(),
            'preferences': {
                'currency': 'USD',
                'date_format': '%Y-%m-%d',
                'reports_frequency': 'weekly'
            }
        }
        return user_id

    def get_user(self, user_id):
        return self.users.get(user_id)

    def get_user_by_username(self, username):
        for user in self.users.values():
            if user['username'] == username:
                return user
        return None

    def update_user_preferences(self, user_id, preferences):
        user = self.get_user(user_id)
        if user:
            user['preferences'] = {**user.get('preferences', {}), **preferences}
            return True
        return False

    # Wallet methods
    def add_wallet(self, name, description, created_by):
        wallet_id = str(uuid.uuid4())
        self.wallets[wallet_id] = {
            'id': wallet_id,
            'name': name,
            'description': description,
            'created_by': created_by,
            'created_at': datetime.now(),
            'budget': 0,
            'budget_period': 'monthly'
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

    def update_wallet_budget(self, wallet_id, budget, period):
        wallet = self.get_wallet(wallet_id)
        if wallet:
            wallet['budget'] = float(budget)
            wallet['budget_period'] = period
            return True
        return False

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

    # Budget Alert methods
    def add_budget_alert(self, wallet_id, alert_type, target, method):
        alert_id = str(uuid.uuid4())
        self.budget_alerts[alert_id] = {
            'id': alert_id,
            'wallet_id': wallet_id,
            'type': alert_type,  # 'threshold', 'monthly', 'weekly'
            'target': target,    # For threshold: percentage (e.g., 80), for time-based: None
            'method': method,    # 'email', 'webhook'
            'enabled': True
        }
        return alert_id

    def get_wallet_alerts(self, wallet_id):
        return [alert for alert in self.budget_alerts.values() if alert['wallet_id'] == wallet_id]

    def delete_alert(self, alert_id):
        if alert_id in self.budget_alerts:
            del self.budget_alerts[alert_id]
            return True
        return False

    # Webhook methods
    def add_webhook(self, wallet_id, url):
        webhook_id = str(uuid.uuid4())
        self.webhooks[webhook_id] = {
            'id': webhook_id,
            'wallet_id': wallet_id,
            'url': url,
            'enabled': True
        }
        return webhook_id

    def get_wallet_webhooks(self, wallet_id):
        return [webhook for webhook in self.webhooks.values() if webhook['wallet_id'] == wallet_id]

    # Reporting methods
    def get_wallet_expense_report(self, wallet_id, period='monthly'):
        expenses = self.get_wallet_expenses(wallet_id)
        if not expenses:
            return None

        # Filter by period
        now = datetime.now()
        if period == 'weekly':
            start_date = now - timedelta(days=now.weekday())
        elif period == 'monthly':
            start_date = datetime(now.year, now.month, 1)
        elif period == 'yearly':
            start_date = datetime(now.year, 1, 1)
        else:  # All time
            start_date = min(exp['date'] for exp in expenses)

        filtered_expenses = [exp for exp in expenses if exp['date'] >= start_date]

        # Calculate totals
        total = sum(exp['amount'] for exp in filtered_expenses)
        by_category = {}
        for exp in filtered_expenses:
            by_category[exp['category']] = by_category.get(exp['category'], 0) + exp['amount']

        # Get budget info
        wallet = self.get_wallet(wallet_id)
        budget = wallet.get('budget', 0)
        budget_period = wallet.get('budget_period', 'monthly')

        # Check if we're in the same period as the budget
        if budget_period != period:
            budget = 0  # Don't compare if periods don't match

        return {
            'period': period,
            'start_date': start_date,
            'end_date': now,
            'total_expenses': total,
            'budget': budget,
            'budget_usage': (total / budget * 100) if budget > 0 else 0,
            'by_category': by_category,
            'expense_count': len(filtered_expenses),
            'average_expense': total / len(filtered_expenses) if filtered_expenses else 0
        }

    def get_spending_trends(self, wallet_id, time_frame='monthly'):
        expenses = self.get_wallet_expenses(wallet_id)
        if not expenses:
            return None

        # Group expenses by time period
        trends = {}
        for exp in expenses:
            if time_frame == 'daily':
                key = exp['date'].strftime('%Y-%m-%d')
            elif time_frame == 'weekly':
                year, week, _ = exp['date'].isocalendar()
                key = f"{year}-W{week:02d}"
            elif time_frame == 'monthly':
                key = exp['date'].strftime('%Y-%m')
            else:  # yearly
                key = exp['date'].strftime('%Y')

            if key not in trends:
                trends[key] = 0
            trends[key] += exp['amount']

        # Sort by date
        sorted_trends = dict(sorted(trends.items()))
        return sorted_trends

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

def send_email_alert(user_email, subject, message):
    """Simulate sending an email alert"""
    print(f"Simulating email to {user_email}:\nSubject: {subject}\n{message}")
    # In a real implementation, you would use SMTP to send an actual email
    return True

def send_webhook_alert(webhook_url, payload):
    """Simulate sending a webhook alert"""
    print(f"Simulating webhook to {webhook_url} with payload: {payload}")
    try:
        # In a real implementation, you would send an actual HTTP request
        # response = requests.post(webhook_url, json=payload, timeout=5)
        # return response.status_code == 200
        return True
    except Exception as e:
        print(f"Webhook error: {e}")
        return False

def check_budget_alerts():
    """Periodically check budget alerts and trigger notifications"""
    while True:
        try:
            print("Checking budget alerts...")
            now = datetime.now()

            for alert_id, alert in db.budget_alerts.items():
                if not alert['enabled']:
                    continue

                wallet_id = alert['wallet_id']
                wallet = db.get_wallet(wallet_id)
                if not wallet:
                    continue

                # Get current spending for the relevant period
                report = db.get_wallet_expense_report(wallet_id, wallet['budget_period'])
                if not report:
                    continue

                # Check if we need to trigger an alert
                trigger = False
                message = ""

                if alert['type'] == 'threshold' and wallet['budget'] > 0:
                    threshold = float(alert['target'])
                    if report['budget_usage'] >= threshold:
                        trigger = True
                        message = (
                            f"Budget Alert: Your wallet '{wallet['name']}' has reached "
                            f"{report['budget_usage']:.0f}% of its {wallet['budget_period']} budget "
                            f"(${report['total_expenses']:.2f} of ${wallet['budget']:.2f})"
                        )

                elif alert['type'] in ['monthly', 'weekly']:
                    # Time-based alerts (send at the end of the period)
                    period = alert['type']
                    if period == 'weekly' and now.weekday() == 6:  # Sunday
                        trigger = True
                    elif period == 'monthly' and now.day == 1:  # First day of month
                        trigger = True

                    if trigger:
                        message = (
                            f"Budget Report: Your wallet '{wallet['name']}' spent "
                            f"${report['total_expenses']:.2f} this {period[:-2]}"
                        )

                if trigger:
                    # Send alert based on method
                    if alert['method'] == 'email':
                        # Send to all wallet admins
                        members = db.get_wallet_members(wallet_id)
                        for member in members:
                            role = db.get_user_wallet_role(member['id'], wallet_id)
                            if role == 'admin':
                                send_email_alert(member['email'], "Budget Alert", message)
                    elif alert['method'] == 'webhook':
                        # Send to all registered webhooks for this wallet
                        webhooks = db.get_wallet_webhooks(wallet_id)
                        for webhook in webhooks:
                            if webhook['enabled']:
                                send_webhook_alert(webhook['url'], {
                                    'wallet_id': wallet_id,
                                    'wallet_name': wallet['name'],
                                    'alert_id': alert_id,
                                    'message': message,
                                    'timestamp': now.isoformat()
                                })

            # Sleep until next check (every hour)
            time.sleep(3600)

        except Exception as e:
            print(f"Error in budget alert check: {e}")
            time.sleep(60)

# Start the budget alert checker in a background thread
alert_thread = threading.Thread(target=check_budget_alerts, daemon=True)
alert_thread.start()

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

        # Add budget info
        report = db.get_wallet_expense_report(wallet['id'], wallet.get('budget_period', 'monthly'))
        if report:
            wallet['budget_usage'] = report['budget_usage']
        else:
            wallet['budget_usage'] = 0

    return render_template('index.html', user=user, wallets=wallets)

@app.route('/reports/<wallet_id>')
def wallet_reports(wallet_id):
    if not has_wallet_permission(wallet_id):
        flash('You do not have permission to view reports for this wallet', 'danger')
        return redirect(url_for('index'))

    wallet = db.get_wallet(wallet_id)
    if not wallet:
        flash('Wallet not found', 'danger')
        return redirect(url_for('index'))

    # Get reports for different periods
    daily_trends = db.get_spending_trends(wallet_id, 'daily')
    weekly_trends = db.get_spending_trends(wallet_id, 'weekly')
    monthly_trends = db.get_spending_trends(wallet_id, 'monthly')

    # Generate charts
    daily_chart = generate_trend_chart(daily_trends, 'Daily Spending')
    weekly_chart = generate_trend_chart(weekly_trends, 'Weekly Spending')
    monthly_chart = generate_trend_chart(monthly_trends, 'Monthly Spending')

    # Get category breakdown
    report = db.get_wallet_expense_report(wallet_id, 'monthly')
    category_chart = generate_category_chart(report['by_category']) if report else None

    # Get budget alerts
    alerts = db.get_wallet_alerts(wallet_id)
    webhooks = db.get_wallet_webhooks(wallet_id)

    return render_template(
        'reports.html',
        wallet=wallet,
        daily_chart=daily_chart,
        weekly_chart=weekly_chart,
        monthly_chart=monthly_chart,
        category_chart=category_chart,
        report=report,
        alerts=alerts,
        webhooks=webhooks
    )

def generate_trend_chart(trend_data, title):
    if not trend_data or len(trend_data) < 2:
        return None

    # Prepare data
    dates = list(trend_data.keys())
    values = list(trend_data.values())

    # Create plot
    plt.figure(figsize=(10, 4))
    plt.plot(dates, values, marker='o', linestyle='-', color='#4361ee')
    plt.title(title)
    plt.xlabel('Date')
    plt.ylabel('Amount')
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Save to buffer
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    img_data = base64.b64encode(buf.read()).decode('utf8')
    plt.close()

    return f"data:image/png;base64,{img_data}"

def generate_category_chart(category_data):
    if not category_data:
        return None

    # Prepare data
    labels = list(category_data.keys())
    values = list(category_data.values())

    # Create plot
    plt.figure(figsize=(8, 8))
    plt.pie(values, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title('Spending by Category')
    plt.axis('equal')
    plt.tight_layout()

    # Save to buffer
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    img_data = base64.b64encode(buf.read()).decode('utf8')
    plt.close()

    return f"data:image/png;base64,{img_data}"

@app.route('/set_budget/<wallet_id>', methods=['POST'])
def set_budget(wallet_id):
    if not has_wallet_permission(wallet_id, 'admin'):
        return jsonify({'success': False, 'message': 'Permission denied'}), 403

    budget = request.form.get('budget')
    period = request.form.get('period')

    if not budget or not period:
        return jsonify({'success': False, 'message': 'Missing parameters'}), 400

    try:
        budget = float(budget)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid budget amount'}), 400

    if db.update_wallet_budget(wallet_id, budget, period):
        return jsonify({'success': True, 'message': 'Budget updated successfully'})

    return jsonify({'success': False, 'message': 'Wallet not found'}), 404

@app.route('/add_alert/<wallet_id>', methods=['POST'])
def add_alert(wallet_id):
    if not has_wallet_permission(wallet_id, 'admin'):
        return jsonify({'success': False, 'message': 'Permission denied'}), 403

    alert_type = request.form.get('type')
    target = request.form.get('target')
    method = request.form.get('method')

    if not alert_type or not method:
        return jsonify({'success': False, 'message': 'Missing parameters'}), 400

    # Validate target for threshold alerts
    if alert_type == 'threshold' and not target:
        return jsonify({'success': False, 'message': 'Threshold value required'}), 400

    if alert_type == 'threshold':
        try:
            target = float(target)
            if target <= 0 or target > 100:
                return jsonify({'success': False, 'message': 'Threshold must be between 1-100'}), 400
        except ValueError:
            return jsonify({'success': False, 'message': 'Invalid threshold value'}), 400

    db.add_budget_alert(wallet_id, alert_type, target, method)
    return jsonify({'success': True, 'message': 'Alert added successfully'})

@app.route('/add_webhook/<wallet_id>', methods=['POST'])
def add_webhook(wallet_id):
    if not has_wallet_permission(wallet_id, 'admin'):
        return jsonify({'success': False, 'message': 'Permission denied'}), 403

    url = request.form.get('url')

    if not url:
        return jsonify({'success': False, 'message': 'Webhook URL required'}), 400

    db.add_webhook(wallet_id, url)
    return jsonify({'success': True, 'message': 'Webhook added successfully'})

@app.route('/toggle_alert/<alert_id>', methods=['POST'])
def toggle_alert(alert_id):
    alert = next((a for a in db.budget_alerts.values() if a['id'] == alert_id), None)
    if not alert:
        return jsonify({'success': False, 'message': 'Alert not found'}), 404

    if not has_wallet_permission(alert['wallet_id'], 'admin'):
        return jsonify({'success': False, 'message': 'Permission denied'}), 403

    alert['enabled'] = not alert['enabled']
    status = "enabled" if alert['enabled'] else "disabled"
    return jsonify({'success': True, 'message': f'Alert {status} successfully'})

@app.route('/delete_alert/<alert_id>', methods=['DELETE'])
def delete_alert(alert_id):
    alert = next((a for a in db.budget_alerts.values() if a['id'] == alert_id), None)
    if not alert:
        return jsonify({'success': False, 'message': 'Alert not found'}), 404

    if not has_wallet_permission(alert['wallet_id'], 'admin'):
        return jsonify({'success': False, 'message': 'Permission denied'}), 403

    db.delete_alert(alert_id)
    return jsonify({'success': True, 'message': 'Alert deleted successfully'})

# ... (other existing routes: register, login, logout, create_wallet, wallet_details, etc.) ...

if __name__ == '__main__':
    app.run(debug=True, threaded=True)
