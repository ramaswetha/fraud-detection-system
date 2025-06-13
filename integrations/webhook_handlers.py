from flask import Blueprint, request, jsonify
import stripe
import json
import hmac
import hashlib
from datetime import datetime
import logging
from fraud_detection_model import FraudDetectionModel
from database import FraudDatabase
from integrations.stripe_integration import StripeIntegration
from integrations.fraud_databases import FraudDatabaseManager

# Create blueprint for webhook handlers
webhooks_bp = Blueprint('webhooks', __name__, url_prefix='/webhooks')

# Initialize components
fraud_detector = FraudDetectionModel()
db = FraudDatabase()
stripe_integration = StripeIntegration()
fraud_db_manager = FraudDatabaseManager()

logger = logging.getLogger(__name__)

@webhooks_bp.route('/stripe', methods=['POST'])
def stripe_webhook():
    """Handle Stripe webhook events"""
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    endpoint_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
    
    if not endpoint_secret:
        logger.error("Stripe webhook secret not configured")
        return jsonify({'error': 'Webhook secret not configured'}), 500
    
    # Verify webhook signature
    if not stripe_integration.verify_webhook_signature(payload, sig_header, endpoint_secret):
        return jsonify({'error': 'Invalid signature'}), 400
    
    try:
        event = json.loads(payload)
        
        # Handle different event types
        if event['type'] == 'charge.succeeded':
            return handle_stripe_charge_succeeded(event)
        elif event['type'] == 'charge.failed':
            return handle_stripe_charge_failed(event)
        elif event['type'] == 'charge.dispute.created':
            return handle_stripe_dispute_created(event)
        elif event['type'] == 'payment_intent.succeeded':
            return handle_stripe_payment_intent_succeeded(event)
        else:
            logger.info(f"Unhandled Stripe event type: {event['type']}")
            return jsonify({'status': 'ignored'}), 200
    
    except Exception as e:
        logger.error(f"Error processing Stripe webhook: {e}")
        return jsonify({'error': 'Webhook processing failed'}), 500

def handle_stripe_charge_succeeded(event):
    """Handle successful Stripe charge"""
    charge = event['data']['object']
    
    # Convert Stripe charge to our transaction format
    transaction_data = stripe_integration._process_stripe_charge(charge)
    
    # Prepare data for fraud analysis
    fraud_analysis_data = {
        'transaction_id': transaction_data['transaction_id'],
        'user_id': transaction_data.get('customer_info', {}).get('customer_id', 'unknown'),
        'amount': transaction_data['amount'],
        'currency': transaction_data['currency'],
        'email': transaction_data.get('customer_info', {}).get('email'),
        'payment_processor': 'stripe',
        'billing_country': transaction_data.get('billing_details', {}).get('address', {}).get('country'),
        'card_country': transaction_data.get('payment_method', {}).get('country'),
        'card_funding': transaction_data.get('payment_method', {}).get('funding'),
        'timestamp': transaction_data['created'].isoformat()
    }
    
    # Analyze with our fraud detection model
    fraud_prediction = fraud_detector.predict_fraud(fraud_analysis_data)
    
    # Analyze with external fraud databases
    external_analysis = fraud_db_manager.analyze_transaction(fraud_analysis_data)
    
    # Combine results
    combined_risk_score = (fraud_prediction['fraud_probability'] + external_analysis['combined_risk_score']) / 2
    combined_risk_factors = fraud_prediction.get('risk_factors', []) + external_analysis.get('risk_factors', [])
    
    # Update prediction with combined results
    fraud_prediction['fraud_probability'] = combined_risk_score
    fraud_prediction['risk_level'] = _get_risk_level(combined_risk_score)
    fraud_prediction['external_analysis'] = external_analysis
    
    # Store in database
    db.insert_transaction(fraud_analysis_data, fraud_prediction)
    
    # Create alert if high risk
    if fraud_prediction['risk_level'] == 'High':
        db.create_fraud_alert(
            transaction_data['transaction_id'],
            'High Risk Stripe Transaction',
            'Critical',
            f"Real-time Stripe transaction flagged as high risk (score: {combined_risk_score:.2%})"
        )
        
        # Log high-risk transaction
        logger.warning(f"High-risk Stripe transaction detected: {transaction_data['transaction_id']}")
    
    return jsonify({
        'status': 'processed',
        'transaction_id': transaction_data['transaction_id'],
        'fraud_score': combined_risk_score,
        'risk_level': fraud_prediction['risk_level']
    }), 200

def handle_stripe_charge_failed(event):
    """Handle failed Stripe charge"""
    charge = event['data']['object']
    
    # Log failed charge for analysis
    logger.info(f"Stripe charge failed: {charge['id']}, reason: {charge.get('failure_message')}")
    
    # Store failed transaction data
    transaction_data = {
        'transaction_id': charge['id'],
        'amount': charge['amount'] / 100,
        'status': 'failed',
        'failure_reason': charge.get('failure_message'),
        'timestamp': datetime.now().isoformat()
    }
    
    # Failed transactions can indicate fraud attempts
    fraud_prediction = {
        'is_fraud': True,
        'fraud_probability': 0.8,
        'risk_level': 'High',
        'reason': 'Transaction failed - potential fraud attempt'
    }
    
    db.insert_transaction(transaction_data, fraud_prediction)
    
    return jsonify({'status': 'logged'}), 200

def handle_stripe_dispute_created(event):
    """Handle Stripe dispute creation"""
    dispute = event['data']['object']
    charge_id = dispute['charge']
    
    # Mark original transaction as disputed (likely fraud)
    logger.warning(f"Dispute created for charge: {charge_id}")
    
    # Create high-priority alert
    db.create_fraud_alert(
        charge_id,
        'Chargeback/Dispute Created',
        'Critical',
        f"Chargeback dispute created for transaction {charge_id}. Amount: ${dispute['amount']/100:.2f}"
    )
    
    return jsonify({'status': 'dispute_logged'}), 200

def handle_stripe_payment_intent_succeeded(event):
    """Handle successful Stripe payment intent"""
    payment_intent = event['data']['object']
    
    # Similar processing to charge.succeeded
    # This is for newer Stripe integrations using Payment Intents
    logger.info(f"Payment intent succeeded: {payment_intent['id']}")
    
    return jsonify({'status': 'processed'}), 200

@webhooks_bp.route('/paypal', methods=['POST'])
def paypal_webhook():
    """Handle PayPal webhook events"""
    try:
        # Verify PayPal webhook signature
        if not verify_paypal_webhook():
            return jsonify({'error': 'Invalid signature'}), 400
        
        event_data = request.get_json()
        event_type = event_data.get('event_type')
        
        if event_type == 'PAYMENT.CAPTURE.COMPLETED':
            return handle_paypal_payment_completed(event_data)
        elif event_type == 'PAYMENT.CAPTURE.DENIED':
            return handle_paypal_payment_denied(event_data)
        else:
            logger.info(f"Unhandled PayPal event type: {event_type}")
            return jsonify({'status': 'ignored'}), 200
    
    except Exception as e:
        logger.error(f"Error processing PayPal webhook: {e}")
        return jsonify({'error': 'Webhook processing failed'}), 500

def verify_paypal_webhook():
    """Verify PayPal webhook signature"""
    # PayPal webhook verification logic
    # This is a simplified version - implement proper verification
    webhook_id = request.headers.get('PAYPAL-TRANSMISSION-ID')
    return webhook_id is not None

def handle_paypal_payment_completed(event_data):
    """Handle completed PayPal payment"""
    resource = event_data.get('resource', {})
    
    # Extract transaction data
    transaction_data = {
        'transaction_id': resource.get('id'),
        'amount': float(resource.get('amount', {}).get('value', 0)),
        'currency': resource.get('amount', {}).get('currency_code'),
        'status': resource.get('status'),
        'payment_processor': 'paypal',
        'timestamp': datetime.now().isoformat()
    }
    
    # Analyze for fraud
    fraud_prediction = fraud_detector.predict_fraud(transaction_data)
    
    # Store in database
    db.insert_transaction(transaction_data, fraud_prediction)
    
    return jsonify({'status': 'processed'}), 200

def handle_paypal_payment_denied(event_data):
    """Handle denied PayPal payment"""
    resource = event_data.get('resource', {})
    
    logger.warning(f"PayPal payment denied: {resource.get('id')}")
    
    # Log as potential fraud attempt
    transaction_data = {
        'transaction_id': resource.get('id'),
        'status': 'denied',
        'payment_processor': 'paypal',
        'timestamp': datetime.now().isoformat()
    }
    
    fraud_prediction = {
        'is_fraud': True,
        'fraud_probability': 0.9,
        'risk_level': 'High',
        'reason': 'PayPal payment denied'
    }
    
    db.insert_transaction(transaction_data, fraud_prediction)
    
    return jsonify({'status': 'logged'}), 200

@webhooks_bp.route('/test', methods=['POST'])
def test_webhook():
    """Test webhook endpoint for development"""
    data = request.get_json()
    logger.info(f"Test webhook received: {data}")
    
    # Process test transaction
    if data and data.get('test_transaction'):
        transaction_data = data['test_transaction']
        fraud_prediction = fraud_detector.predict_fraud(transaction_data)
        db.insert_transaction(transaction_data, fraud_prediction)
        
        return jsonify({
            'status': 'test_processed',
            'fraud_prediction': fraud_prediction
        }), 200
    
    return jsonify({'status': 'test_received'}), 200

def _get_risk_level(probability):
    """Convert probability to risk level"""
    if probability < 0.3:
        return 'Low'
    elif probability < 0.7:
        return 'Medium'
    else:
        return 'High'

# Error handlers
@webhooks_bp.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request'}), 400

@webhooks_bp.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500
