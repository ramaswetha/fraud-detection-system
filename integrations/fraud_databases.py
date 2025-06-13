import os
import requests
import json
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging
import sqlite3

class MaxMindIntegration:
    """Integration with MaxMind minFraud service for fraud detection"""
    
    def __init__(self, account_id: str = None, license_key: str = None):
        self.account_id = account_id or os.getenv('MAXMIND_ACCOUNT_ID')
        self.license_key = license_key or os.getenv('MAXMIND_LICENSE_KEY')
        self.base_url = 'https://minfraud.maxmind.com/minfraud/v2.0'
        self.logger = logging.getLogger(__name__)
    
    def score_transaction(self, transaction_data: Dict) -> Dict:
        """Get fraud score from MaxMind minFraud"""
        try:
            url = f"{self.base_url}/score"
            
            # Prepare request data in MaxMind format
            request_data = self._prepare_maxmind_request(transaction_data)
            
            response = requests.post(
                url,
                json=request_data,
                auth=(self.account_id, self.license_key),
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result = response.json()
                return self._process_maxmind_response(result)
            else:
                self.logger.error(f"MaxMind API error: {response.text}")
                return {'error': 'API request failed'}
        
        except Exception as e:
            self.logger.error(f"Error calling MaxMind API: {e}")
            return {'error': str(e)}
    
    def _prepare_maxmind_request(self, transaction_data: Dict) -> Dict:
        """Convert transaction data to MaxMind format"""
        request_data = {
            'device': {
                'ip_address': transaction_data.get('ip_address', '127.0.0.1'),
                'user_agent': transaction_data.get('user_agent', ''),
                'accept_language': transaction_data.get('accept_language', 'en-US')
            },
            'event': {
                'transaction_id': transaction_data.get('transaction_id'),
                'shop_id': transaction_data.get('shop_id', 'default'),
                'time': transaction_data.get('timestamp', datetime.now().isoformat()),
                'type': 'purchase'
            },
            'account': {
                'user_id': transaction_data.get('user_id'),
                'username_md5': self._hash_if_exists(transaction_data.get('username'))
            },
            'email': {
                'address': transaction_data.get('email'),
                'domain': transaction_data.get('email', '').split('@')[-1] if transaction_data.get('email') else None
            },
            'billing': {
                'first_name': transaction_data.get('billing_first_name'),
                'last_name': transaction_data.get('billing_last_name'),
                'company': transaction_data.get('billing_company'),
                'address': transaction_data.get('billing_address'),
                'address_2': transaction_data.get('billing_address_2'),
                'city': transaction_data.get('billing_city'),
                'region': transaction_data.get('billing_region'),
                'country': transaction_data.get('billing_country'),
                'postal': transaction_data.get('billing_postal'),
                'phone_number': transaction_data.get('billing_phone')
            },
            'payment': {
                'processor': transaction_data.get('payment_processor', 'stripe'),
                'was_authorized': transaction_data.get('was_authorized', True),
                'decline_code': transaction_data.get('decline_code')
            },
            'order': {
                'amount': transaction_data.get('amount', 0),
                'currency': transaction_data.get('currency', 'USD'),
                'discount_code': transaction_data.get('discount_code'),
                'affiliate_id': transaction_data.get('affiliate_id'),
                'subaffiliate_id': transaction_data.get('subaffiliate_id'),
                'referrer_uri': transaction_data.get('referrer_uri')
            }
        }
        
        # Remove None values
        return self._remove_none_values(request_data)
    
    def _hash_if_exists(self, value: str) -> Optional[str]:
        """Hash a value with MD5 if it exists"""
        if value:
            return hashlib.md5(value.encode()).hexdigest()
        return None
    
    def _remove_none_values(self, data: Dict) -> Dict:
        """Recursively remove None values from dictionary"""
        if isinstance(data, dict):
            return {k: self._remove_none_values(v) for k, v in data.items() if v is not None}
        return data
    
    def _process_maxmind_response(self, response: Dict) -> Dict:
        """Process MaxMind response into our format"""
        risk_score = response.get('risk_score', 0) / 100  # Convert to 0-1 scale
        
        # Extract risk factors
        risk_factors = []
        subscores = response.get('subscores', {})
        
        if subscores.get('billing_address', 0) > 50:
            risk_factors.append('suspicious_billing_address')
        if subscores.get('country_match', 0) < 50:
            risk_factors.append('country_mismatch')
        if subscores.get('email_address', 0) > 50:
            risk_factors.append('suspicious_email')
        
        return {
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'maxmind_score': response.get('risk_score'),
            'subscores': subscores,
            'ip_address': response.get('ip_address', {}),
            'credit_card': response.get('credit_card', {}),
            'device': response.get('device', {}),
            'email': response.get('email', {}),
            'warnings': response.get('warnings', [])
        }

class SiftIntegration:
    """Integration with Sift fraud detection service"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('SIFT_API_KEY')
        self.base_url = 'https://api.sift.com/v205'
        self.logger = logging.getLogger(__name__)
    
    def send_transaction_event(self, transaction_data: Dict) -> Dict:
        """Send transaction event to Sift"""
        try:
            url = f"{self.base_url}/events"
            
            # Prepare Sift event data
            event_data = self._prepare_sift_event(transaction_data)
            
            response = requests.post(
                url,
                json=event_data,
                params={'api_key': self.api_key},
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f"Sift API error: {response.text}")
                return {'error': 'API request failed'}
        
        except Exception as e:
            self.logger.error(f"Error calling Sift API: {e}")
            return {'error': str(e)}
    
    def get_user_score(self, user_id: str) -> Dict:
        """Get user fraud score from Sift"""
        try:
            url = f"{self.base_url}/score/{user_id}"
            
            response = requests.get(
                url,
                params={'api_key': self.api_key}
            )
            
            if response.status_code == 200:
                result = response.json()
                return self._process_sift_score(result)
            else:
                self.logger.error(f"Sift score API error: {response.text}")
                return {'error': 'API request failed'}
        
        except Exception as e:
            self.logger.error(f"Error getting Sift score: {e}")
            return {'error': str(e)}
    
    def _prepare_sift_event(self, transaction_data: Dict) -> Dict:
        """Convert transaction data to Sift event format"""
        return {
            '$type': '$transaction',
            '$api_key': self.api_key,
            '$user_id': transaction_data.get('user_id'),
            '$transaction_id': transaction_data.get('transaction_id'),
            '$user_email': transaction_data.get('email'),
            '$amount': int(transaction_data.get('amount', 0) * 1000000),  # Convert to micros
            '$currency_code': transaction_data.get('currency', 'USD'),
            '$time': int(datetime.now().timestamp() * 1000),  # Convert to milliseconds
            '$transaction_type': '$sale',
            '$transaction_status': '$success',
            '$ip': transaction_data.get('ip_address'),
            '$billing_address': {
                '$name': f"{transaction_data.get('billing_first_name', '')} {transaction_data.get('billing_last_name', '')}".strip(),
                '$address_1': transaction_data.get('billing_address'),
                '$city': transaction_data.get('billing_city'),
                '$region': transaction_data.get('billing_region'),
                '$country': transaction_data.get('billing_country'),
                '$zipcode': transaction_data.get('billing_postal')
            },
            '$payment_method': {
                '$payment_type': '$credit_card',
                '$payment_gateway': transaction_data.get('payment_processor', 'stripe'),
                '$card_bin': transaction_data.get('card_bin'),
                '$card_last4': transaction_data.get('card_last4')
            }
        }
    
    def _process_sift_score(self, response: Dict) -> Dict:
        """Process Sift score response"""
        score = response.get('score', 0)
        risk_score = score / 100  # Convert to 0-1 scale
        
        # Determine risk factors based on score
        risk_factors = []
        if score > 70:
            risk_factors.append('high_sift_score')
        if score > 50:
            risk_factors.append('elevated_sift_score')
        
        return {
            'risk_score': risk_score,
            'sift_score': score,
            'risk_factors': risk_factors,
            'reasons': response.get('reasons', []),
            'latest_decisions': response.get('latest_decisions', {})
        }

class FraudDatabaseManager:
    """Manages multiple fraud database integrations"""
    
    def __init__(self, db_path: str = 'fraud_intelligence.db'):
        self.db_path = db_path
        self.maxmind = MaxMindIntegration()
        self.sift = SiftIntegration()
        self.init_database()
        self.logger = logging.getLogger(__name__)
    
    def init_database(self):
        """Initialize fraud intelligence database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create fraud intelligence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS fraud_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT NOT NULL,
                source TEXT NOT NULL,
                risk_score REAL,
                risk_factors TEXT,
                raw_response TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create IP reputation table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_reputation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                risk_score REAL,
                country TEXT,
                is_proxy BOOLEAN,
                is_vpn BOOLEAN,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create email reputation table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_reputation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_hash TEXT UNIQUE NOT NULL,
                risk_score REAL,
                is_disposable BOOLEAN,
                domain_age_days INTEGER,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def analyze_transaction(self, transaction_data: Dict) -> Dict:
        """Analyze transaction using multiple fraud databases"""
        results = {
            'combined_risk_score': 0.0,
            'risk_factors': [],
            'source_results': {}
        }
        
        # MaxMind analysis
        if self.maxmind.account_id and self.maxmind.license_key:
            maxmind_result = self.maxmind.score_transaction(transaction_data)
            if 'error' not in maxmind_result:
                results['source_results']['maxmind'] = maxmind_result
                results['combined_risk_score'] += maxmind_result.get('risk_score', 0) * 0.4
                results['risk_factors'].extend(maxmind_result.get('risk_factors', []))
                
                # Store in database
                self._store_fraud_intelligence(
                    transaction_data.get('transaction_id'),
                    'maxmind',
                    maxmind_result
                )
        
        # Sift analysis
        if self.sift.api_key:
            # Send transaction event
            sift_event_result = self.sift.send_transaction_event(transaction_data)
            
            # Get user score
            if transaction_data.get('user_id'):
                sift_score_result = self.sift.get_user_score(transaction_data['user_id'])
                if 'error' not in sift_score_result:
                    results['source_results']['sift'] = sift_score_result
                    results['combined_risk_score'] += sift_score_result.get('risk_score', 0) * 0.3
                    results['risk_factors'].extend(sift_score_result.get('risk_factors', []))
                    
                    # Store in database
                    self._store_fraud_intelligence(
                        transaction_data.get('transaction_id'),
                        'sift',
                        sift_score_result
                    )
        
        # Internal reputation checks
        internal_result = self._check_internal_reputation(transaction_data)
        results['source_results']['internal'] = internal_result
        results['combined_risk_score'] += internal_result.get('risk_score', 0) * 0.3
        results['risk_factors'].extend(internal_result.get('risk_factors', []))
        
        # Normalize combined score
        results['combined_risk_score'] = min(results['combined_risk_score'], 1.0)
        
        # Remove duplicate risk factors
        results['risk_factors'] = list(set(results['risk_factors']))
        
        return results
    
    def _check_internal_reputation(self, transaction_data: Dict) -> Dict:
        """Check internal reputation databases"""
        risk_score = 0.0
        risk_factors = []
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check IP reputation
        ip_address = transaction_data.get('ip_address')
        if ip_address:
            cursor.execute(
                'SELECT risk_score, is_proxy, is_vpn FROM ip_reputation WHERE ip_address = ?',
                (ip_address,)
            )
            ip_result = cursor.fetchone()
            if ip_result:
                ip_risk, is_proxy, is_vpn = ip_result
                risk_score += ip_risk * 0.5
                if is_proxy:
                    risk_factors.append('proxy_ip')
                if is_vpn:
                    risk_factors.append('vpn_ip')
        
        # Check email reputation
        email = transaction_data.get('email')
        if email:
            email_hash = hashlib.md5(email.lower().encode()).hexdigest()
            cursor.execute(
                'SELECT risk_score, is_disposable FROM email_reputation WHERE email_hash = ?',
                (email_hash,)
            )
            email_result = cursor.fetchone()
            if email_result:
                email_risk, is_disposable = email_result
                risk_score += email_risk * 0.3
                if is_disposable:
                    risk_factors.append('disposable_email')
        
        conn.close()
        
        return {
            'risk_score': min(risk_score, 1.0),
            'risk_factors': risk_factors
        }
    
    def _store_fraud_intelligence(self, transaction_id: str, source: str, result: Dict):
        """Store fraud intelligence results in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO fraud_intelligence 
            (transaction_id, source, risk_score, risk_factors, raw_response)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            transaction_id,
            source,
            result.get('risk_score'),
            json.dumps(result.get('risk_factors', [])),
            json.dumps(result)
        ))
        
        conn.commit()
        conn.close()
    
    def update_ip_reputation(self, ip_address: str, risk_score: float, 
                           country: str = None, is_proxy: bool = False, is_vpn: bool = False):
        """Update IP reputation data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO ip_reputation 
            (ip_address, risk_score, country, is_proxy, is_vpn, last_updated)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (ip_address, risk_score, country, is_proxy, is_vpn))
        
        conn.commit()
        conn.close()
    
    def update_email_reputation(self, email: str, risk_score: float, 
                              is_disposable: bool = False, domain_age_days: int = None):
        """Update email reputation data"""
        email_hash = hashlib.md5(email.lower().encode()).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO email_reputation 
            (email_hash, risk_score, is_disposable, domain_age_days, last_updated)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (email_hash, risk_score, is_disposable, domain_age_days))
        
        conn.commit()
        conn.close()

# Example usage
if __name__ == "__main__":
    # Initialize fraud database manager
    fraud_db = FraudDatabaseManager()
    
    # Sample transaction data
    sample_transaction = {
        'transaction_id': 'TXN_TEST_001',
        'user_id': 'USER_123',
        'amount': 1500.0,
        'currency': 'USD',
        'email': 'test@example.com',
        'ip_address': '192.168.1.1',
        'billing_first_name': 'John',
        'billing_last_name': 'Doe',
        'billing_address': '123 Main St',
        'billing_city': 'New York',
        'billing_region': 'NY',
        'billing_country': 'US',
        'billing_postal': '10001',
        'payment_processor': 'stripe'
    }
    
    # Analyze transaction
    print("Analyzing transaction with fraud databases...")
    result = fraud_db.analyze_transaction(sample_transaction)
    print(f"Combined risk score: {result['combined_risk_score']:.2f}")
    print(f"Risk factors: {result['risk_factors']}")
    print(f"Source results: {result['source_results']}")
