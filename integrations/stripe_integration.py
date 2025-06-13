import stripe
import os
from datetime import datetime, timedelta
import requests
from typing import Dict, List, Optional
import logging

class StripeIntegration:
    def __init__(self, api_key: str = None):
        """Initialize Stripe integration"""
        self.api_key = api_key or os.getenv('STRIPE_SECRET_KEY')
        if self.api_key:
            stripe.api_key = self.api_key
        self.logger = logging.getLogger(__name__)
    
    def get_recent_charges(self, limit: int = 100, hours_back: int = 24) -> List[Dict]:
        """Fetch recent charges from Stripe"""
        try:
            # Calculate timestamp for filtering
            since_timestamp = int((datetime.now() - timedelta(hours=hours_back)).timestamp())
            
            charges = stripe.Charge.list(
                limit=limit,
                created={'gte': since_timestamp}
            )
            
            processed_charges = []
            for charge in charges.data:
                processed_charge = self._process_stripe_charge(charge)
                processed_charges.append(processed_charge)
            
            return processed_charges
        
        except stripe.error.StripeError as e:
            self.logger.error(f"Stripe API error: {e}")
            return []
    
    def get_charge_details(self, charge_id: str) -> Optional[Dict]:
        """Get detailed information about a specific charge"""
        try:
            charge = stripe.Charge.retrieve(charge_id)
            return self._process_stripe_charge(charge)
        except stripe.error.StripeError as e:
            self.logger.error(f"Error retrieving charge {charge_id}: {e}")
            return None
    
    def _process_stripe_charge(self, charge) -> Dict:
        """Process Stripe charge data into our format"""
        # Extract customer information
        customer_info = {}
        if charge.customer:
            try:
                customer = stripe.Customer.retrieve(charge.customer)
                customer_info = {
                    'customer_id': customer.id,
                    'email': customer.email,
                    'created': customer.created,
                    'default_source': customer.default_source
                }
            except:
                pass
        
        # Extract payment method details
        payment_method = {}
        if charge.payment_method_details:
            pm_details = charge.payment_method_details
            if pm_details.card:
                payment_method = {
                    'brand': pm_details.card.brand,
                    'country': pm_details.card.country,
                    'exp_month': pm_details.card.exp_month,
                    'exp_year': pm_details.card.exp_year,
                    'funding': pm_details.card.funding,
                    'last4': pm_details.card.last4,
                    'network': pm_details.card.network,
                    'three_d_secure': pm_details.card.three_d_secure,
                    'wallet': pm_details.card.wallet
                }
        
        # Calculate risk indicators
        risk_indicators = self._calculate_stripe_risk_indicators(charge, customer_info, payment_method)
        
        return {
            'transaction_id': charge.id,
            'amount': charge.amount / 100,  # Convert from cents
            'currency': charge.currency,
            'status': charge.status,
            'created': datetime.fromtimestamp(charge.created),
            'description': charge.description,
            'customer_info': customer_info,
            'payment_method': payment_method,
            'billing_details': charge.billing_details,
            'outcome': charge.outcome,
            'risk_level': charge.outcome.risk_level if charge.outcome else 'normal',
            'seller_message': charge.outcome.seller_message if charge.outcome else None,
            'risk_indicators': risk_indicators,
            'metadata': charge.metadata,
            'receipt_email': charge.receipt_email,
            'source_transfer': charge.source_transfer,
            'statement_descriptor': charge.statement_descriptor
        }
    
    def _calculate_stripe_risk_indicators(self, charge, customer_info: Dict, payment_method: Dict) -> Dict:
        """Calculate additional risk indicators from Stripe data"""
        risk_score = 0.0
        risk_factors = []
        
        # High amount risk
        amount_usd = charge.amount / 100
        if amount_usd > 1000:
            risk_score += 0.2
            risk_factors.append('high_amount')
        
        # New customer risk
        if customer_info and customer_info.get('created'):
            account_age_days = (datetime.now().timestamp() - customer_info['created']) / 86400
            if account_age_days < 7:
                risk_score += 0.3
                risk_factors.append('new_customer')
        
        # International card risk
        if payment_method.get('country') and payment_method['country'] != 'US':
            risk_score += 0.1
            risk_factors.append('international_card')
        
        # Prepaid card risk
        if payment_method.get('funding') == 'prepaid':
            risk_score += 0.2
            risk_factors.append('prepaid_card')
        
        # Failed 3D Secure
        if payment_method.get('three_d_secure') and payment_method['three_d_secure'].get('result') == 'failed':
            risk_score += 0.4
            risk_factors.append('failed_3ds')
        
        # Stripe's own risk assessment
        if charge.outcome:
            if charge.outcome.risk_level == 'elevated':
                risk_score += 0.3
                risk_factors.append('stripe_elevated_risk')
            elif charge.outcome.risk_level == 'highest':
                risk_score += 0.5
                risk_factors.append('stripe_highest_risk')
        
        return {
            'risk_score': min(risk_score, 1.0),
            'risk_factors': risk_factors,
            'stripe_risk_level': charge.outcome.risk_level if charge.outcome else 'normal'
        }
    
    def create_webhook_endpoint(self, url: str, events: List[str] = None) -> Dict:
        """Create a webhook endpoint for real-time notifications"""
        if not events:
            events = [
                'charge.succeeded',
                'charge.failed',
                'charge.dispute.created',
                'payment_intent.succeeded',
                'payment_intent.payment_failed'
            ]
        
        try:
            webhook_endpoint = stripe.WebhookEndpoint.create(
                url=url,
                enabled_events=events
            )
            return {
                'id': webhook_endpoint.id,
                'url': webhook_endpoint.url,
                'secret': webhook_endpoint.secret,
                'status': webhook_endpoint.status
            }
        except stripe.error.StripeError as e:
            self.logger.error(f"Error creating webhook: {e}")
            return {}
    
    def verify_webhook_signature(self, payload: bytes, sig_header: str, endpoint_secret: str) -> bool:
        """Verify webhook signature from Stripe"""
        try:
            stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
            return True
        except ValueError:
            self.logger.error("Invalid payload")
            return False
        except stripe.error.SignatureVerificationError:
            self.logger.error("Invalid signature")
            return False

class PayPalIntegration:
    def __init__(self, client_id: str = None, client_secret: str = None, sandbox: bool = True):
        """Initialize PayPal integration"""
        self.client_id = client_id or os.getenv('PAYPAL_CLIENT_ID')
        self.client_secret = client_secret or os.getenv('PAYPAL_CLIENT_SECRET')
        self.sandbox = sandbox
        self.base_url = 'https://api.sandbox.paypal.com' if sandbox else 'https://api.paypal.com'
        self.access_token = None
        self.logger = logging.getLogger(__name__)
    
    def get_access_token(self) -> str:
        """Get OAuth access token from PayPal"""
        try:
            url = f"{self.base_url}/v1/oauth2/token"
            headers = {
                'Accept': 'application/json',
                'Accept-Language': 'en_US',
            }
            data = 'grant_type=client_credentials'
            
            response = requests.post(
                url, 
                headers=headers, 
                data=data,
                auth=(self.client_id, self.client_secret)
            )
            
            if response.status_code == 200:
                self.access_token = response.json()['access_token']
                return self.access_token
            else:
                self.logger.error(f"Failed to get PayPal access token: {response.text}")
                return None
        
        except Exception as e:
            self.logger.error(f"Error getting PayPal access token: {e}")
            return None
    
    def get_payment_details(self, payment_id: str) -> Optional[Dict]:
        """Get payment details from PayPal"""
        if not self.access_token:
            self.get_access_token()
        
        try:
            url = f"{self.base_url}/v1/payments/payment/{payment_id}"
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.access_token}'
            }
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                payment_data = response.json()
                return self._process_paypal_payment(payment_data)
            else:
                self.logger.error(f"Failed to get PayPal payment: {response.text}")
                return None
        
        except Exception as e:
            self.logger.error(f"Error getting PayPal payment details: {e}")
            return None
    
    def _process_paypal_payment(self, payment_data: Dict) -> Dict:
        """Process PayPal payment data into our format"""
        # Extract transaction details
        transactions = payment_data.get('transactions', [])
        if not transactions:
            return {}
        
        transaction = transactions[0]
        amount = transaction.get('amount', {})
        
        # Extract payer information
        payer = payment_data.get('payer', {})
        payer_info = payer.get('payer_info', {})
        
        # Calculate risk indicators
        risk_indicators = self._calculate_paypal_risk_indicators(payment_data)
        
        return {
            'transaction_id': payment_data.get('id'),
            'amount': float(amount.get('total', 0)),
            'currency': amount.get('currency'),
            'status': payment_data.get('state'),
            'created': payment_data.get('create_time'),
            'payer_email': payer_info.get('email'),
            'payer_id': payer_info.get('payer_id'),
            'payer_status': payer_info.get('status'),
            'country_code': payer_info.get('country_code'),
            'payment_method': payer.get('payment_method'),
            'risk_indicators': risk_indicators,
            'description': transaction.get('description'),
            'item_list': transaction.get('item_list', {}),
            'related_resources': transaction.get('related_resources', [])
        }
    
    def _calculate_paypal_risk_indicators(self, payment_data: Dict) -> Dict:
        """Calculate risk indicators from PayPal data"""
        risk_score = 0.0
        risk_factors = []
        
        # Check transaction amount
        transactions = payment_data.get('transactions', [])
        if transactions:
            amount = float(transactions[0].get('amount', {}).get('total', 0))
            if amount > 1000:
                risk_score += 0.2
                risk_factors.append('high_amount')
        
        # Check payer status
        payer_info = payment_data.get('payer', {}).get('payer_info', {})
        if payer_info.get('status') == 'UNVERIFIED':
            risk_score += 0.3
            risk_factors.append('unverified_payer')
        
        # Check for international transactions
        country_code = payer_info.get('country_code')
        if country_code and country_code != 'US':
            risk_score += 0.1
            risk_factors.append('international_transaction')
        
        return {
            'risk_score': min(risk_score, 1.0),
            'risk_factors': risk_factors
        }

# Example usage and testing
if __name__ == "__main__":
    # Test Stripe integration
    stripe_integration = StripeIntegration()
    print("Testing Stripe integration...")
    
    # Test PayPal integration
    paypal_integration = PayPalIntegration()
    print("Testing PayPal integration...")
