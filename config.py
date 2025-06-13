import os
from typing import Dict, Optional

class FraudDetectionConfig:
    """Configuration management for fraud detection system"""
    
    def __init__(self):
        self.load_config()
    
    def load_config(self):
        """Load configuration from environment variables"""
        
        # Database Configuration
        self.DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///fraud_detection.db')
        self.FRAUD_INTELLIGENCE_DB = os.getenv('FRAUD_INTELLIGENCE_DB', 'fraud_intelligence.db')
        
        # Stripe Configuration
        self.STRIPE_SECRET_KEY = os.getenv('STRIPE_SECRET_KEY')
        self.STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY')
        self.STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET')
        
        # PayPal Configuration
        self.PAYPAL_CLIENT_ID = os.getenv('PAYPAL_CLIENT_ID')
        self.PAYPAL_CLIENT_SECRET = os.getenv('PAYPAL_CLIENT_SECRET')
        self.PAYPAL_SANDBOX = os.getenv('PAYPAL_SANDBOX', 'true').lower() == 'true'
        
        # MaxMind Configuration
        self.MAXMIND_ACCOUNT_ID = os.getenv('MAXMIND_ACCOUNT_ID')
        self.MAXMIND_LICENSE_KEY = os.getenv('MAXMIND_LICENSE_KEY')
        
        # Sift Configuration
        self.SIFT_API_KEY = os.getenv('SIFT_API_KEY')
        
        # Alert Configuration
        self.FRAUD_ALERT_WEBHOOK_URL = os.getenv('FRAUD_ALERT_WEBHOOK_URL')
        self.FRAUD_ALERT_EMAIL = os.getenv('FRAUD_ALERT_EMAIL')
        self.EMAIL_SMTP_SERVER = os.getenv('EMAIL_SMTP_SERVER')
        self.EMAIL_SMTP_PORT = int(os.getenv('EMAIL_SMTP_PORT', '587'))
        self.EMAIL_USERNAME = os.getenv('EMAIL_USERNAME')
        self.EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
        
        # Real-time Processing Configuration
        self.ENABLE_REAL_TIME_PROCESSING = os.getenv('ENABLE_REAL_TIME_PROCESSING', 'true').lower() == 'true'
        self.MAX_PROCESSING_THREADS = int(os.getenv('MAX_PROCESSING_THREADS', '5'))
        self.MAX_ALERT_THREADS = int(os.getenv('MAX_ALERT_THREADS', '2'))
        self.BATCH_SIZE = int(os.getenv('BATCH_SIZE', '10'))
        self.PROCESSING_INTERVAL = int(os.getenv('PROCESSING_INTERVAL', '1'))
        
        # Risk Thresholds
        self.LOW_RISK_THRESHOLD = float(os.getenv('LOW_RISK_THRESHOLD', '0.3'))
        self.HIGH_RISK_THRESHOLD = float(os.getenv('HIGH_RISK_THRESHOLD', '0.7'))
        
        # Model Configuration
        self.MODEL_UPDATE_INTERVAL_HOURS = int(os.getenv('MODEL_UPDATE_INTERVAL_HOURS', '24'))
        self.MIN_TRAINING_SAMPLES = int(os.getenv('MIN_TRAINING_SAMPLES', '1000'))
        
        # API Rate Limiting
        self.MAXMIND_RATE_LIMIT = int(os.getenv('MAXMIND_RATE_LIMIT', '1000'))  # requests per hour
        self.SIFT_RATE_LIMIT = int(os.getenv('SIFT_RATE_LIMIT', '10000'))  # requests per hour
        
        # Logging Configuration
        self.LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
        self.LOG_FILE = os.getenv('LOG_FILE', 'fraud_detection.log')
        
        # Feature Flags
        self.ENABLE_BEHAVIORAL_BIOMETRICS = os.getenv('ENABLE_BEHAVIORAL_BIOMETRICS', 'true').lower() == 'true'
        self.ENABLE_EXTERNAL_FRAUD_CHECKS = os.getenv('ENABLE_EXTERNAL_FRAUD_CHECKS', 'true').lower() == 'true'
        self.ENABLE_IP_GEOLOCATION = os.getenv('ENABLE_IP_GEOLOCATION', 'true').lower() == 'true'
    
    def validate_config(self) -> Dict[str, bool]:
        """Validate configuration and return status"""
        validation_results = {}
        
        # Check Stripe configuration
        validation_results['stripe_configured'] = bool(self.STRIPE_SECRET_KEY)
        
        # Check PayPal configuration
        validation_results['paypal_configured'] = bool(
            self.PAYPAL_CLIENT_ID and self.PAYPAL_CLIENT_SECRET
        )
        
        # Check MaxMind configuration
        validation_results['maxmind_configured'] = bool(
            self.MAXMIND_ACCOUNT_ID and self.MAXMIND_LICENSE_KEY
        )
        
        # Check Sift configuration
        validation_results['sift_configured'] = bool(self.SIFT_API_KEY)
        
        # Check email configuration
        validation_results['email_configured'] = bool(
            self.EMAIL_SMTP_SERVER and self.EMAIL_USERNAME and self.EMAIL_PASSWORD
        )
        
        return validation_results
    
    def get_config_summary(self) -> Dict:
        """Get configuration summary for display"""
        validation = self.validate_config()
        
        return {
            'integrations': {
                'stripe': validation['stripe_configured'],
                'paypal': validation['paypal_configured'],
                'maxmind': validation['maxmind_configured'],
                'sift': validation['sift_configured']
            },
            'features': {
                'real_time_processing': self.ENABLE_REAL_TIME_PROCESSING,
                'behavioral_biometrics': self.ENABLE_BEHAVIORAL_BIOMETRICS,
                'external_fraud_checks': self.ENABLE_EXTERNAL_FRAUD_CHECKS,
                'ip_geolocation': self.ENABLE_IP_GEOLOCATION
            },
            'thresholds': {
                'low_risk': self.LOW_RISK_THRESHOLD,
                'high_risk': self.HIGH_RISK_THRESHOLD
            },
            'processing': {
                'max_threads': self.MAX_PROCESSING_THREADS,
                'batch_size': self.BATCH_SIZE,
                'interval_seconds': self.PROCESSING_INTERVAL
            }
        }

# Global configuration instance
config = FraudDetectionConfig()
