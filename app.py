from flask import Flask, render_template, request, jsonify, redirect, url_for
import json
import uuid
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
from fraud_detection_model import FraudDetectionModel
from database import FraudDatabase
import os
from integrations.stripe_integration import StripeIntegration
from integrations.fraud_databases import FraudDatabaseManager
from integrations.webhook_handlers import webhooks_bp
from real_time_processor import RealTimeFraudProcessor
from config import config
import os

app = Flask(__name__)
app.secret_key = 'fraud_detection_secret_key'

# Initialize fraud detection system
fraud_detector = FraudDetectionModel()
db = FraudDatabase()

# Try to load pre-trained models
try:
    fraud_detector.load_models()
    print("Pre-trained models loaded successfully!")
except:
    print("No pre-trained models found. Training new models...")
    # Generate and train on synthetic data
    df = fraud_detector.generate_synthetic_data(n_samples=5000)
    fraud_detector.train_models(df)
    fraud_detector.save_models()
    print("New models trained and saved!")

# Initialize integrations
stripe_integration = StripeIntegration()
fraud_db_manager = FraudDatabaseManager()

# Initialize real-time processor if enabled
real_time_processor = None
if config.ENABLE_REAL_TIME_PROCESSING:
    real_time_processor = RealTimeFraudProcessor()
    real_time_processor.start()
    print("Real-time fraud processor started!")

# Register webhook blueprint
app.register_blueprint(webhooks_bp)

@app.route('/')
def dashboard():
    """Main dashboard showing fraud detection statistics"""
    stats = db.get_fraud_statistics()
    recent_transactions = db.get_recent_transactions(limit=10)
    open_alerts = db.get_open_alerts()
    
    # Get fraud trends for the last 7 days
    trends = db.get_fraud_trends(days=7)
    
    return render_template('dashboard.html', 
                         stats=stats,
                         recent_transactions=recent_transactions.to_dict('records'),
                         open_alerts=open_alerts.to_dict('records'),
                         trends=trends.to_dict('records'))

@app.route('/analyze', methods=['GET', 'POST'])
def analyze_transaction():
    """Analyze a single transaction for fraud"""
    if request.method == 'POST':
        try:
            # Get transaction data from form
            transaction_data = {
                'transaction_id': request.form.get('transaction_id') or f"TXN_{uuid.uuid4().hex[:8]}",
                'user_id': request.form.get('user_id'),
                'amount': float(request.form.get('amount', 0)),
                'merchant': request.form.get('merchant'),
                'transaction_amount': float(request.form.get('amount', 0)),
                'account_age_days': int(request.form.get('account_age_days', 30)),
                'num_transactions_today': int(request.form.get('num_transactions_today', 1)),
                'avg_transaction_amount': float(request.form.get('avg_transaction_amount', 100)),
                'time_since_last_transaction': int(request.form.get('time_since_last_transaction', 60)),
                'merchant_risk_score': float(request.form.get('merchant_risk_score', 0.1)),
                'location_risk_score': float(request.form.get('location_risk_score', 0.1)),
                'device_risk_score': float(request.form.get('device_risk_score', 0.1)),
                'velocity_score': float(request.form.get('velocity_score', 0.1)),
                'amount_deviation': float(request.form.get('amount_deviation', 0.5)),
                'hour_of_day': int(request.form.get('hour_of_day', 12)),
                'day_of_week': int(request.form.get('day_of_week', 1)),
                'is_weekend': int(request.form.get('is_weekend', 0)),
                'cross_border': int(request.form.get('cross_border', 0)),
                'high_risk_merchant': int(request.form.get('high_risk_merchant', 0))
            }
            
            # Get model type
            model_type = request.form.get('model_type', 'ensemble')
            
            # Predict fraud
            prediction = fraud_detector.predict_fraud(transaction_data, model_type)
            
            # Store in database
            db.insert_transaction(transaction_data, prediction)
            
            # Create alert if high risk
            if prediction['risk_level'] == 'High':
                db.create_fraud_alert(
                    transaction_data['transaction_id'],
                    'High Risk Transaction',
                    'Critical',
                    f"Transaction flagged as high risk fraud (probability: {prediction['fraud_probability']:.2%})"
                )
            
            return render_template('analyze.html', 
                                 transaction=transaction_data,
                                 prediction=prediction,
                                 analyzed=True)
        
        except Exception as e:
            return render_template('analyze.html', 
                                 error=f"Error analyzing transaction: {str(e)}")
    
    return render_template('analyze.html')

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for fraud analysis"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['amount', 'user_id']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Add transaction ID if not provided
        if 'transaction_id' not in data:
            data['transaction_id'] = f"TXN_{uuid.uuid4().hex[:8]}"
        
        # Set default values for missing features
        defaults = {
            'account_age_days': 30,
            'num_transactions_today': 1,
            'avg_transaction_amount': 100,
            'time_since_last_transaction': 60,
            'merchant_risk_score': 0.1,
            'location_risk_score': 0.1,
            'device_risk_score': 0.1,
            'velocity_score': 0.1,
            'amount_deviation': 0.5,
            'hour_of_day': datetime.now().hour,
            'day_of_week': datetime.now().weekday(),
            'is_weekend': 1 if datetime.now().weekday() >= 5 else 0,
            'cross_border': 0,
            'high_risk_merchant': 0
        }
        
        for key, value in defaults.items():
            if key not in data:
                data[key] = value
        
        # Ensure transaction_amount is set
        data['transaction_amount'] = data['amount']
        
        # Predict fraud
        prediction = fraud_detector.predict_fraud(data)
        
        # Store in database
        db.insert_transaction(data, prediction)
        
        # Create alert if high risk
        if prediction['risk_level'] == 'High':
            db.create_fraud_alert(
                data['transaction_id'],
                'High Risk Transaction',
                'Critical',
                f"Transaction flagged as high risk fraud (probability: {prediction['fraud_probability']:.2%})"
            )
        
        return jsonify({
            'transaction_id': data['transaction_id'],
            'prediction': prediction,
            'status': 'success'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/alerts')
def alerts():
    """View fraud alerts"""
    open_alerts = db.get_open_alerts()
    return render_template('alerts.html', alerts=open_alerts.to_dict('records'))

@app.route('/transactions')
def transactions():
    """View recent transactions"""
    recent_transactions = db.get_recent_transactions(limit=50)
    return render_template('transactions.html', 
                         transactions=recent_transactions.to_dict('records'))

@app.route('/api/stats')
def api_stats():
    """API endpoint for fraud statistics"""
    stats = db.get_fraud_statistics()
    trends = db.get_fraud_trends(days=7)
    
    return jsonify({
        'statistics': stats,
        'trends': trends.to_dict('records')
    })

@app.route('/demo')
def demo():
    """Demo page with sample transactions"""
    sample_transactions = [
        {
            'name': 'Normal Transaction',
            'amount': 50.0,
            'merchant': 'Coffee Shop',
            'account_age_days': 365,
            'merchant_risk_score': 0.1,
            'cross_border': 0,
            'high_risk_merchant': 0
        },
        {
            'name': 'Suspicious Transaction',
            'amount': 2500.0,
            'merchant': 'Unknown Merchant',
            'account_age_days': 5,
            'merchant_risk_score': 0.8,
            'cross_border': 1,
            'high_risk_merchant': 1
        },
        {
            'name': 'High-Value Transaction',
            'amount': 5000.0,
            'merchant': 'Electronics Store',
            'account_age_days': 100,
            'merchant_risk_score': 0.3,
            'cross_border': 0,
            'high_risk_merchant': 0
        }
    ]
    
    return render_template('demo.html', sample_transactions=sample_transactions)

@app.route('/config')
def config_status():
    """Show configuration status"""
    config_summary = config.get_config_summary()
    validation_results = config.validate_config()
    
    return render_template('config.html', 
                         config_summary=config_summary,
                         validation_results=validation_results)

@app.route('/integrations')
def integrations():
    """Show integration status and recent data"""
    integration_data = {}
    
    # Get Stripe data if configured
    if config.STRIPE_SECRET_KEY:
        try:
            recent_charges = stripe_integration.get_recent_charges(limit=10, hours_back=24)
            integration_data['stripe'] = {
                'status': 'connected',
                'recent_charges': len(recent_charges),
                'charges': recent_charges[:5]  # Show first 5
            }
        except Exception as e:
            integration_data['stripe'] = {
                'status': 'error',
                'error': str(e)
            }
    else:
        integration_data['stripe'] = {'status': 'not_configured'}
    
    # Get real-time processor stats
    if real_time_processor:
        integration_data['real_time_processor'] = real_time_processor.get_statistics()
    
    return render_template('integrations.html', integration_data=integration_data)

@app.route('/api/sync/stripe', methods=['POST'])
def sync_stripe_data():
    """Manually sync Stripe data"""
    if not config.STRIPE_SECRET_KEY:
        return jsonify({'error': 'Stripe not configured'}), 400
    
    try:
        hours_back = request.json.get('hours_back', 24) if request.is_json else 24
        recent_charges = stripe_integration.get_recent_charges(limit=100, hours_back=hours_back)
        
        processed_count = 0
        for charge_data in recent_charges:
            # Convert to our transaction format
            transaction_data = {
                'transaction_id': charge_data['transaction_id'],
                'user_id': charge_data.get('customer_info', {}).get('customer_id', 'unknown'),
                'amount': charge_data['amount'],
                'currency': charge_data['currency'],
                'email': charge_data.get('customer_info', {}).get('email'),
                'payment_processor': 'stripe',
                'timestamp': charge_data['created'].isoformat()
            }
            
            # Analyze with fraud detection
            fraud_prediction = fraud_detector.predict_fraud(transaction_data)
            
            # Analyze with external databases
            external_analysis = fraud_db_manager.analyze_transaction(transaction_data)
            
            # Combine results
            combined_score = (fraud_prediction['fraud_probability'] + external_analysis['combined_risk_score']) / 2
            fraud_prediction['fraud_probability'] = combined_score
            fraud_prediction['risk_level'] = 'High' if combined_score > 0.7 else 'Medium' if combined_score > 0.3 else 'Low'
            
            # Store in database
            db.insert_transaction(transaction_data, fraud_prediction)
            processed_count += 1
        
        return jsonify({
            'status': 'success',
            'processed_count': processed_count,
            'message': f'Synced {processed_count} Stripe transactions'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Create templates directory and basic templates if they don't exist
    os.makedirs('templates', exist_ok=True)
    
    # Create a simple base template
    base_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Fraud Detection System</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #2c3e50; color: white; padding: 20px; margin: -20px -20px 20px -20px; border-radius: 8px 8px 0 0; }
        .nav { margin: 20px 0; }
        .nav a { margin-right: 20px; color: #3498db; text-decoration: none; }
        .nav a:hover { text-decoration: underline; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: #ecf0f1; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 2em; font-weight: bold; color: #2c3e50; }
        .stat-label { color: #7f8c8d; margin-top: 5px; }
        .form-group { margin: 15px 0; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input, .form-group select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        .btn { background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #2980b9; }
        .alert { padding: 15px; margin: 10px 0; border-radius: 4px; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-danger { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .alert-warning { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
        .table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .table th, .table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .table th { background: #f8f9fa; font-weight: bold; }
        .risk-high { color: #e74c3c; font-weight: bold; }
        .risk-medium { color: #f39c12; font-weight: bold; }
        .risk-low { color: #27ae60; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ AI-Powered Fraud Detection System</h1>
            <p>Real-time fraud detection with machine learning and behavioral biometrics</p>
        </div>
        
        <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/analyze">Analyze Transaction</a>
            <a href="/transactions">Transactions</a>
            <a href="/alerts">Alerts</a>
            <a href="/demo">Demo</a>
        </div>
        
        {% block content %}{% endblock %}
    </div>
</body>
</html>'''
    
    with open('templates/base.html', 'w') as f:
        f.write(base_template)
    
    # Dashboard template
    dashboard_template = '''{% extends "base.html" %}
{% block content %}
<h2>📊 Fraud Detection Dashboard</h2>

<div class="stats">
    <div class="stat-card">
        <div class="stat-value">{{ stats.total_transactions }}</div>
        <div class="stat-label">Total Transactions</div>
    </div>
    <div class="stat-card">
        <div class="stat-value">{{ "%.1f"|format(stats.fraud_rate) }}%</div>
        <div class="stat-label">Fraud Rate</div>
    </div>
    <div class="stat-card">
        <div class="stat-value">{{ stats.high_risk_transactions }}</div>
        <div class="stat-label">High Risk Transactions</div>
    </div>
    <div class="stat-card">
        <div class="stat-value">{{ stats.open_alerts }}</div>
        <div class="stat-label">Open Alerts</div>
    </div>
</div>

<h3>🔍 Recent Transactions</h3>
<table class="table">
    <thead>
        <tr>
            <th>Transaction ID</th>
            <th>User ID</th>
            <th>Amount</th>
            <th>Fraud Probability</th>
            <th>Risk Level</th>
            <th>Timestamp</th>
        </tr>
    </thead>
    <tbody>
        {% for transaction in recent_transactions %}
        <tr>
            <td>{{ transaction.transaction_id }}</td>
            <td>{{ transaction.user_id }}</td>
            <td>${{ "%.2f"|format(transaction.amount) }}</td>
            <td>{{ "%.1f"|format(transaction.fraud_probability * 100) }}%</td>
            <td class="risk-{{ transaction.risk_level.lower() }}">{{ transaction.risk_level }}</td>
            <td>{{ transaction.timestamp }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>

<h3>🚨 Recent Alerts</h3>
{% if open_alerts %}
<table class="table">
    <thead>
        <tr>
            <th>Transaction ID</th>
            <th>Alert Type</th>
            <th>Severity</th>
            <th>Amount</th>
            <th>Fraud Probability</th>
            <th>Created</th>
        </tr>
    </thead>
    <tbody>
        {% for alert in open_alerts %}
        <tr>
            <td>{{ alert.transaction_id }}</td>
            <td>{{ alert.alert_type }}</td>
            <td class="risk-{{ alert.severity.lower() }}">{{ alert.severity }}</td>
            <td>${{ "%.2f"|format(alert.amount) }}</td>
            <td>{{ "%.1f"|format(alert.fraud_probability * 100) }}%</td>
            <td>{{ alert.created_at }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% else %}
<div class="alert alert-success">No open alerts - all transactions are within normal parameters.</div>
{% endif %}
{% endblock %}'''
    
    with open('templates/dashboard.html', 'w') as f:
        f.write(dashboard_template)
    
    # Analyze template
    analyze_template = '''{% extends "base.html" %}
{% block content %}
<h2>🔍 Analyze Transaction</h2>

{% if error %}
<div class="alert alert-danger">{{ error }}</div>
{% endif %}

{% if analyzed %}
<div class="alert alert-{{ 'danger' if prediction.is_fraud else 'success' }}">
    <h3>Analysis Results</h3>
    <p><strong>Transaction ID:</strong> {{ transaction.transaction_id }}</p>
    <p><strong>Fraud Detected:</strong> {{ "Yes" if prediction.is_fraud else "No" }}</p>
    <p><strong>Fraud Probability:</strong> {{ "%.1f"|format(prediction.fraud_probability * 100) }}%</p>
    <p><strong>Risk Level:</strong> <span class="risk-{{ prediction.risk_level.lower() }}">{{ prediction.risk_level }}</span></p>
</div>
{% endif %}

<form method="POST">
    <h3>Transaction Details</h3>
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
        <div>
            <div class="form-group">
                <label>Transaction ID (optional):</label>
                <input type="text" name="transaction_id" placeholder="Auto-generated if empty">
            </div>
            <div class="form-group">
                <label>User ID:</label>
                <input type="text" name="user_id" required placeholder="USER_123">
            </div>
            <div class="form-group">
                <label>Amount ($):</label>
                <input type="number" name="amount" step="0.01" required placeholder="100.00">
            </div>
            <div class="form-group">
                <label>Merchant:</label>
                <input type="text" name="merchant" placeholder="Store Name">
            </div>
            <div class="form-group">
                <label>Account Age (days):</label>
                <input type="number" name="account_age_days" value="30" min="1">
            </div>
            <div class="form-group">
                <label>Transactions Today:</label>
                <input type="number" name="num_transactions_today" value="1" min="1">
            </div>
            <div class="form-group">
                <label>Average Transaction Amount ($):</label>
                <input type="number" name="avg_transaction_amount" step="0.01" value="100.00">
            </div>
            <div class="form-group">
                <label>Time Since Last Transaction (minutes):</label>
                <input type="number" name="time_since_last_transaction" value="60">
            </div>
        </div>
        <div>
            <div class="form-group">
                <label>Merchant Risk Score (0-1):</label>
                <input type="number" name="merchant_risk_score" step="0.1" value="0.1" min="0" max="1">
            </div>
            <div class="form-group">
                <label>Location Risk Score (0-1):</label>
                <input type="number" name="location_risk_score" step="0.1" value="0.1" min="0" max="1">
            </div>
            <div class="form-group">
                <label>Device Risk Score (0-1):</label>
                <input type="number" name="device_risk_score" step="0.1" value="0.1" min="0" max="1">
            </div>
            <div class="form-group">
                <label>Hour of Day (0-23):</label>
                <input type="number" name="hour_of_day" value="12" min="0" max="23">
            </div>
            <div class="form-group">
                <label>Day of Week (0-6):</label>
                <input type="number" name="day_of_week" value="1" min="0" max="6">
            </div>
            <div class="form-group">
                <label>Is Weekend:</label>
                <select name="is_weekend">
                    <option value="0">No</option>
                    <option value="1">Yes</option>
                </select>
            </div>
            <div class="form-group">
                <label>Cross Border:</label>
                <select name="cross_border">
                    <option value="0">No</option>
                    <option value="1">Yes</option>
                </select>
            </div>
            <div class="form-group">
                <label>High Risk Merchant:</label>
                <select name="high_risk_merchant">
                    <option value="0">No</option>
                    <option value="1">Yes</option>
                </select>
            </div>
        </div>
    </div>
    
    <div class="form-group">
        <label>Model Type:</label>
        <select name="model_type">
            <option value="ensemble">Ensemble (RF + SVM)</option>
            <option value="rf">Random Forest</option>
            <option value="svm">Support Vector Machine</option>
        </select>
    </div>
    
    <button type="submit" class="btn">Analyze Transaction</button>
</form>
{% endblock %}'''
    
    with open('templates/analyze.html', 'w') as f:
        f.write(analyze_template)
    
    # Demo template
    demo_template = '''{% extends "base.html" %}
{% block content %}
<h2>🎯 Demo - Sample Transactions</h2>

<p>Try these pre-configured sample transactions to see the fraud detection system in action:</p>

{% for sample in sample_transactions %}
<div class="alert alert-{{ 'warning' if 'Suspicious' in sample.name else 'success' if 'Normal' in sample.name else 'danger' }}">
    <h3>{{ sample.name }}</h3>
    <form method="POST" action="/analyze" style="display: inline;">
        <input type="hidden" name="amount" value="{{ sample.amount }}">
        <input type="hidden" name="merchant" value="{{ sample.merchant }}">
        <input type="hidden" name="account_age_days" value="{{ sample.account_age_days }}">
        <input type="hidden" name="merchant_risk_score" value="{{ sample.merchant_risk_score }}">
        <input type="hidden" name="cross_border" value="{{ sample.cross_border }}">
        <input type="hidden" name="high_risk_merchant" value="{{ sample.high_risk_merchant }}">
        <input type="hidden" name="user_id" value="DEMO_USER">
        
        <p><strong>Amount:</strong> ${{ sample.amount }} | <strong>Merchant:</strong> {{ sample.merchant }}</p>
        <button type="submit" class="btn">Analyze This Transaction</button>
    </form>
</div>
{% endfor %}

<h3>📡 API Usage Example</h3>
<div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
    <h4>POST /api/analyze</h4>
    <pre style="background: #2c3e50; color: white; padding: 15px; border-radius: 4px; overflow-x: auto;">
curl -X POST http://localhost:5000/api/analyze \\
  -H "Content-Type: application/json" \\
  -d '{
    "user_id": "USER_123",
    "amount": 1500.0,
    "merchant": "Online Store",
    "account_age_days": 30,
    "merchant_risk_score": 0.7,
    "cross_border": 1
  }'</pre>
</div>

<h3>🔧 System Features</h3>
<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0;">
    <div class="stat-card">
        <h4>🤖 Machine Learning</h4>
        <p>Random Forest and SVM algorithms with ensemble prediction for 90%+ accuracy</p>
    </div>
    <div class="stat-card">
        <h4>⚡ Real-time Detection</h4>
        <p>Instant fraud scoring with risk level classification and automated alerts</p>
    </div>
    <div class="stat-card">
        <h4>📊 Analytics Dashboard</h4>
        <p>Comprehensive fraud statistics, trends analysis, and transaction monitoring</p>
    </div>
</div>
{% endblock %}'''
    
    with open('templates/demo.html', 'w') as f:
        f.write(demo_template)
    
    print("Flask app starting...")
    print("Visit http://localhost:5000 to access the fraud detection dashboard")
    app.run(debug=True, host='0.0.0.0', port=5000)
