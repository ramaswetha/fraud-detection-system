import sqlite3
import json
from datetime import datetime
import pandas as pd

class FraudDatabase:
    def __init__(self, db_path='fraud_detection.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the SQLite database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create transactions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT UNIQUE NOT NULL,
                user_id TEXT NOT NULL,
                amount REAL NOT NULL,
                merchant TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_fraud INTEGER DEFAULT 0,
                fraud_probability REAL DEFAULT 0.0,
                risk_level TEXT DEFAULT 'Low',
                model_version TEXT DEFAULT 'v1.0',
                features TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        
        # Create fraud_alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS fraud_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT,
                status TEXT DEFAULT 'open',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                resolved_at DATETIME,
                FOREIGN KEY (transaction_id) REFERENCES transactions (transaction_id)
            )
        ''')
        
        # Create model_performance table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS model_performance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_name TEXT NOT NULL,
                accuracy REAL,
                precision_score REAL,
                recall REAL,
                f1_score REAL,
                false_positive_rate REAL,
                evaluation_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                dataset_size INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()
        print("Database initialized successfully!")
    
    def insert_transaction(self, transaction_data, prediction_result):
        """Insert a new transaction with fraud prediction results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO transactions 
                (transaction_id, user_id, amount, merchant, is_fraud, 
                 fraud_probability, risk_level, features)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                transaction_data.get('transaction_id'),
                transaction_data.get('user_id'),
                transaction_data.get('amount'),
                transaction_data.get('merchant', 'Unknown'),
                1 if prediction_result['is_fraud'] else 0,
                prediction_result['fraud_probability'],
                prediction_result['risk_level'],
                json.dumps(transaction_data)
            ))
            
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError as e:
            print(f"Transaction already exists: {e}")
            return None
        finally:
            conn.close()
    
    
    def create_fraud_alert(self, transaction_id, alert_type, severity, message):
        """Create a fraud alert for high-risk transactions"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO fraud_alerts (transaction_id, alert_type, severity, message)
            VALUES (?, ?, ?, ?)
        ''', (transaction_id, alert_type, severity, message))
        
        conn.commit()
        conn.close()
    
    def get_recent_transactions(self, limit=100):
        """Get recent transactions with fraud predictions"""
        conn = sqlite3.connect(self.db_path)
        
        df = pd.read_sql_query('''
            SELECT 
                transaction_id,
                user_id,
                amount,
                merchant,
                timestamp,
                is_fraud,
                fraud_probability,
                risk_level
            FROM transactions 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', conn, params=(limit,))
        
        conn.close()
        return df
    
    def get_fraud_statistics(self):
        """Get fraud detection statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total transactions
        cursor.execute('SELECT COUNT(*) FROM transactions')
        total_transactions = cursor.fetchone()[0]
        
        # Fraud transactions
        cursor.execute('SELECT COUNT(*) FROM transactions WHERE is_fraud = 1')
        fraud_transactions = cursor.fetchone()[0]
        
        # High risk transactions
        cursor.execute("SELECT COUNT(*) FROM transactions WHERE risk_level = 'High'")
        high_risk_transactions = cursor.fetchone()[0]
        
        # Average fraud probability
        cursor.execute('SELECT AVG(fraud_probability) FROM transactions')
        avg_fraud_prob = cursor.fetchone()[0] or 0
        
        # Open alerts
        cursor.execute("SELECT COUNT(*) FROM fraud_alerts WHERE status = 'open'")
        open_alerts = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_transactions': total_transactions,
            'fraud_transactions': fraud_transactions,
            'fraud_rate': fraud_transactions / max(total_transactions, 1) * 100,
            'high_risk_transactions': high_risk_transactions,
            'avg_fraud_probability': avg_fraud_prob,
            'open_alerts': open_alerts
        }
    
    def get_fraud_trends(self, days=7):
        """Get fraud trends over the last N days"""
        conn = sqlite3.connect(self.db_path)
        
        df = pd.read_sql_query('''
            SELECT 
                DATE(timestamp) as date,
                COUNT(*) as total_transactions,
                SUM(is_fraud) as fraud_transactions,
                AVG(fraud_probability) as avg_fraud_probability
            FROM transactions 
            WHERE timestamp >= datetime('now', '-{} days')
            GROUP BY DATE(timestamp)
            ORDER BY date
        '''.format(days), conn)
        
        conn.close()
        return df
    
    def get_open_alerts(self):
        """Get all open fraud alerts"""
        conn = sqlite3.connect(self.db_path)
        
        df = pd.read_sql_query('''
            SELECT 
                fa.id,
                fa.transaction_id,
                fa.alert_type,
                fa.severity,
                fa.message,
                fa.created_at,
                t.amount,
                t.user_id,
                t.fraud_probability
            FROM fraud_alerts fa
            JOIN transactions t ON fa.transaction_id = t.transaction_id
            WHERE fa.status = 'open'
            ORDER BY fa.created_at DESC
        ''', conn)
        
        conn.close()
        return df

# Demonstration
if __name__ == "__main__":
    # Initialize database
    db = FraudDatabase()
    
    # Sample transaction data
    sample_transaction = {
        'transaction_id': 'TXN_001',
        'user_id': 'USER_123',
        'amount': 1500.0,
        'merchant': 'Online Store XYZ'
    }
    
    sample_prediction = {
        'is_fraud': True,
        'fraud_probability': 0.85,
        'risk_level': 'High'
    }
    
    
    
    # Insert sample data
    transaction_id = db.insert_transaction(sample_transaction, sample_prediction)
    if transaction_id:
        
        db.create_fraud_alert('TXN_001', 'High Risk Transaction', 'Critical', 
                             'Transaction flagged as high risk fraud')
    
    # Get statistics
    stats = db.get_fraud_statistics()
    print("Fraud Detection Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Get recent transactions
    recent = db.get_recent_transactions(limit=10)
    print(f"\nRecent Transactions: {len(recent)} records")
    
    # Get open alerts
    alerts = db.get_open_alerts()
    print(f"Open Alerts: {len(alerts)} alerts")
