import asyncio
import aiohttp
import json
from datetime import datetime, timedelta
import logging
from typing import Dict, List
import threading
import time
from queue import Queue
from fraud_detection_model import FraudDetectionModel
from database import FraudDatabase
from integrations.stripe_integration import StripeIntegration
from integrations.fraud_databases import FraudDatabaseManager

class RealTimeFraudProcessor:
    """Real-time fraud detection processor for live transactions"""
    
    def __init__(self):
        self.fraud_detector = FraudDetectionModel()
        self.db = FraudDatabase()
        self.stripe_integration = StripeIntegration()
        self.fraud_db_manager = FraudDatabaseManager()
        
        # Processing queues
        self.transaction_queue = Queue()
        self.alert_queue = Queue()
        
        # Processing threads
        self.processing_threads = []
        self.alert_threads = []
        
        # Configuration
        self.max_processing_threads = 5
        self.max_alert_threads = 2
        self.batch_size = 10
        self.processing_interval = 1  # seconds
        
        # Statistics
        self.processed_count = 0
        self.fraud_detected_count = 0
        self.start_time = datetime.now()
        
        self.logger = logging.getLogger(__name__)
        self.running = False
    
    def start(self):
        """Start the real-time processing system"""
        self.running = True
        
        # Start processing threads
        for i in range(self.max_processing_threads):
            thread = threading.Thread(target=self._process_transactions, daemon=True)
            thread.start()
            self.processing_threads.append(thread)
        
        # Start alert processing threads
        for i in range(self.max_alert_threads):
            thread = threading.Thread(target=self._process_alerts, daemon=True)
            thread.start()
            self.alert_threads.append(thread)
        
        # Start periodic tasks
        stats_thread = threading.Thread(target=self._periodic_stats, daemon=True)
        stats_thread.start()
        
        sync_thread = threading.Thread(target=self._sync_external_data, daemon=True)
        sync_thread.start()
        
        self.logger.info("Real-time fraud processor started")
    
    def stop(self):
        """Stop the real-time processing system"""
        self.running = False
        self.logger.info("Real-time fraud processor stopped")
    
    def add_transaction(self, transaction_data: Dict):
        """Add transaction to processing queue"""
        transaction_data['received_at'] = datetime.now().isoformat()
        self.transaction_queue.put(transaction_data)
    
    def _process_transactions(self):
        """Process transactions from the queue"""
        while self.running:
            try:
                # Get batch of transactions
                transactions = []
                for _ in range(self.batch_size):
                    if not self.transaction_queue.empty():
                        transactions.append(self.transaction_queue.get())
                    else:
                        break
                
                if transactions:
                    self._process_transaction_batch(transactions)
                else:
                    time.sleep(self.processing_interval)
            
            except Exception as e:
                self.logger.error(f"Error in transaction processing thread: {e}")
                time.sleep(1)
    
    def _process_transaction_batch(self, transactions: List[Dict]):
        """Process a batch of transactions"""
        for transaction_data in transactions:
            try:
                start_time = time.time()
                
                # Enrich transaction data
                enriched_data = self._enrich_transaction_data(transaction_data)
                
                # Run fraud detection
                fraud_prediction = self.fraud_detector.predict_fraud(enriched_data)
                
                # Run external fraud analysis
                external_analysis = self.fraud_db_manager.analyze_transaction(enriched_data)
                
                # Combine results
                combined_result = self._combine_fraud_results(fraud_prediction, external_analysis)
                
                # Store results
                self.db.insert_transaction(enriched_data, combined_result)
                
                # Check for alerts
                if combined_result['risk_level'] == 'High':
                    self._queue_alert(enriched_data, combined_result)
                
                # Update statistics
                self.processed_count += 1
                if combined_result['is_fraud']:
                    self.fraud_detected_count += 1
                
                processing_time = time.time() - start_time
                self.logger.debug(f"Processed transaction {enriched_data.get('transaction_id')} in {processing_time:.3f}s")
            
            except Exception as e:
                self.logger.error(f"Error processing transaction: {e}")
    
    def _enrich_transaction_data(self, transaction_data: Dict) -> Dict:
        """Enrich transaction data with additional features"""
        enriched = transaction_data.copy()
        
        # Add timestamp features
        now = datetime.now()
        enriched['hour_of_day'] = now.hour
        enriched['day_of_week'] = now.weekday()
        enriched['is_weekend'] = 1 if now.weekday() >= 5 else 0
        
        # Add user history features
        user_id = enriched.get('user_id')
        if user_id:
            user_stats = self._get_user_statistics(user_id)
            enriched.update(user_stats)
        
        # Add merchant features
        merchant = enriched.get('merchant')
        if merchant:
            merchant_stats = self._get_merchant_statistics(merchant)
            enriched.update(merchant_stats)
        
        # Add velocity features
        velocity_stats = self._calculate_velocity_features(enriched)
        enriched.update(velocity_stats)
        
        return enriched
    
    def _get_user_statistics(self, user_id: str) -> Dict:
        """Get user historical statistics"""
        # Query recent user transactions
        recent_transactions = self.db.get_recent_transactions(limit=100)
        user_transactions = [t for t in recent_transactions.to_dict('records') if t.get('user_id') == user_id]
        
        if not user_transactions:
            return {
                'user_transaction_count': 0,
                'user_avg_amount': 0,
                'user_fraud_rate': 0
            }
        
        total_amount = sum(t.get('amount', 0) for t in user_transactions)
        fraud_count = sum(1 for t in user_transactions if t.get('is_fraud'))
        
        return {
            'user_transaction_count': len(user_transactions),
            'user_avg_amount': total_amount / len(user_transactions),
            'user_fraud_rate': fraud_count / len(user_transactions)
        }
    
    def _get_merchant_statistics(self, merchant: str) -> Dict:
        """Get merchant historical statistics"""
        # This would typically query a merchant database
        # For now, return default values
        return {
            'merchant_risk_score': 0.1,
            'merchant_fraud_rate': 0.05
        }
    
    def _calculate_velocity_features(self, transaction_data: Dict) -> Dict:
        """Calculate velocity-based features"""
        user_id = transaction_data.get('user_id')
        amount = transaction_data.get('amount', 0)
        
        # Get recent transactions for velocity calculation
        recent_transactions = self.db.get_recent_transactions(limit=1000)
        user_recent = [t for t in recent_transactions.to_dict('records') 
                      if t.get('user_id') == user_id and 
                      datetime.fromisoformat(t.get('timestamp', '1970-01-01')) > datetime.now() - timedelta(hours=24)]
        
        if not user_recent:
            return {
                'num_transactions_today': 1,
                'velocity_score': 0.1,
                'amount_deviation': 0.5
            }
        
        # Calculate velocity metrics
        amounts = [t.get('amount', 0) for t in user_recent]
        avg_amount = sum(amounts) / len(amounts) if amounts else 0
        
        amount_deviation = abs(amount - avg_amount) / max(avg_amount, 1) if avg_amount > 0 else 0
        velocity_score = min(len(user_recent) / 10, 1.0)  # Normalize to 0-1
        
        return {
            'num_transactions_today': len(user_recent) + 1,
            'velocity_score': velocity_score,
            'amount_deviation': amount_deviation,
            'avg_transaction_amount': avg_amount
        }
    
    def _combine_fraud_results(self, internal_result: Dict, external_result: Dict) -> Dict:
        """Combine internal and external fraud analysis results"""
        # Weight the scores
        internal_weight = 0.6
        external_weight = 0.4
        
        combined_score = (
            internal_result['fraud_probability'] * internal_weight +
            external_result['combined_risk_score'] * external_weight
        )
        
        # Combine risk factors
        all_risk_factors = []
        all_risk_factors.extend(internal_result.get('risk_factors', []))
        all_risk_factors.extend(external_result.get('risk_factors', []))
        all_risk_factors = list(set(all_risk_factors))  # Remove duplicates
        
        return {
            'is_fraud': combined_score > 0.5,
            'fraud_probability': combined_score,
            'risk_level': self._get_risk_level(combined_score),
            'risk_factors': all_risk_factors,
            'internal_result': internal_result,
            'external_result': external_result,
            'timestamp': datetime.now().isoformat()
        }
    
    def _get_risk_level(self, probability: float) -> str:
        """Convert probability to risk level"""
        if probability < 0.3:
            return 'Low'
        elif probability < 0.7:
            return 'Medium'
        else:
            return 'High'
    
    def _queue_alert(self, transaction_data: Dict, fraud_result: Dict):
        """Queue high-risk transaction for alerting"""
        alert_data = {
            'transaction_id': transaction_data.get('transaction_id'),
            'user_id': transaction_data.get('user_id'),
            'amount': transaction_data.get('amount'),
            'fraud_probability': fraud_result['fraud_probability'],
            'risk_factors': fraud_result['risk_factors'],
            'timestamp': datetime.now().isoformat()
        }
        self.alert_queue.put(alert_data)
    
    def _process_alerts(self):
        """Process fraud alerts"""
        while self.running:
            try:
                if not self.alert_queue.empty():
                    alert_data = self.alert_queue.get()
                    self._send_fraud_alert(alert_data)
                else:
                    time.sleep(1)
            
            except Exception as e:
                self.logger.error(f"Error in alert processing thread: {e}")
                time.sleep(1)
    
    def _send_fraud_alert(self, alert_data: Dict):
        """Send fraud alert notifications"""
        try:
            # Store alert in database
            self.db.create_fraud_alert(
                alert_data['transaction_id'],
                'Real-time High Risk Transaction',
                'Critical',
                f"Transaction {alert_data['transaction_id']} flagged as high risk "
                f"(probability: {alert_data['fraud_probability']:.2%})"
            )
            
            # Send email notification (if configured)
            self._send_email_alert(alert_data)
            
            # Send webhook notification (if configured)
            self._send_webhook_alert(alert_data)
            
            self.logger.warning(f"Fraud alert sent for transaction: {alert_data['transaction_id']}")
        
        except Exception as e:
            self.logger.error(f"Error sending fraud alert: {e}")
    
    def _send_email_alert(self, alert_data: Dict):
        """Send email alert (placeholder)"""
        # Implement email sending logic here
        # Could use SendGrid, AWS SES, etc.
        pass
    
    def _send_webhook_alert(self, alert_data: Dict):
        """Send webhook alert to external systems"""
        webhook_url = os.getenv('FRAUD_ALERT_WEBHOOK_URL')
        if webhook_url:
            try:
                import requests
                response = requests.post(webhook_url, json=alert_data, timeout=5)
                if response.status_code == 200:
                    self.logger.info(f"Webhook alert sent successfully")
                else:
                    self.logger.error(f"Webhook alert failed: {response.status_code}")
            except Exception as e:
                self.logger.error(f"Error sending webhook alert: {e}")
    
    def _periodic_stats(self):
        """Periodically log processing statistics"""
        while self.running:
            try:
                time.sleep(60)  # Log stats every minute
                
                uptime = datetime.now() - self.start_time
                fraud_rate = (self.fraud_detected_count / max(self.processed_count, 1)) * 100
                
                self.logger.info(
                    f"Fraud Processor Stats - "
                    f"Uptime: {uptime}, "
                    f"Processed: {self.processed_count}, "
                    f"Fraud Detected: {self.fraud_detected_count}, "
                    f"Fraud Rate: {fraud_rate:.2f}%, "
                    f"Queue Size: {self.transaction_queue.qsize()}"
                )
            
            except Exception as e:
                self.logger.error(f"Error in stats thread: {e}")
    
    def _sync_external_data(self):
        """Periodically sync data with external sources"""
        while self.running:
            try:
                time.sleep(300)  # Sync every 5 minutes
                
                # Sync recent Stripe transactions
                if self.stripe_integration.api_key:
                    recent_charges = self.stripe_integration.get_recent_charges(limit=50, hours_back=1)
                    for charge in recent_charges:
                        # Process if not already processed
                        existing = self.db.get_recent_transactions(limit=1000)
                        existing_ids = [t['transaction_id'] for t in existing.to_dict('records')]
                        
                        if charge['transaction_id'] not in existing_ids:
                            self.add_transaction(charge)
                
                self.logger.info("External data sync completed")
            
            except Exception as e:
                self.logger.error(f"Error in sync thread: {e}")
    
    def get_statistics(self) -> Dict:
        """Get current processing statistics"""
        uptime = datetime.now() - self.start_time
        fraud_rate = (self.fraud_detected_count / max(self.processed_count, 1)) * 100
        
        return {
            'uptime_seconds': uptime.total_seconds(),
            'processed_count': self.processed_count,
            'fraud_detected_count': self.fraud_detected_count,
            'fraud_rate_percent': fraud_rate,
            'queue_size': self.transaction_queue.qsize(),
            'alert_queue_size': self.alert_queue.qsize(),
            'processing_threads': len(self.processing_threads),
            'alert_threads': len(self.alert_threads)
        }

# Example usage
if __name__ == "__main__":
    import os
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize and start processor
    processor = RealTimeFraudProcessor()
    processor.start()
    
    # Simulate some transactions
    sample_transactions = [
        {
            'transaction_id': f'RT_TXN_{i:03d}',
            'user_id': f'USER_{i % 10}',
            'amount': 100 + (i * 50),
            'merchant': 'Test Merchant',
            'payment_processor': 'stripe'
        }
        for i in range(20)
    ]
    
    # Add transactions to processor
    for transaction in sample_transactions:
        processor.add_transaction(transaction)
        time.sleep(0.1)  # Small delay between transactions
    
    # Let it process for a while
    time.sleep(10)
    
    # Print statistics
    stats = processor.get_statistics()
    print("Processing Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Stop processor
    processor.stop()
