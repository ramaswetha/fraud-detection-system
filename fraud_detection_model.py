import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.datasets import make_classification
import joblib
import json
from datetime import datetime
import sqlite3

class FraudDetectionModel:
    def __init__(self):
        self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.svm_model = SVC(probability=True, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        
    def generate_synthetic_data(self, n_samples=10000):
        """Generate synthetic transaction data for demonstration"""
        # Create base features
        X, y = make_classification(
            n_samples=n_samples,
            n_features=15,
            n_informative=10,
            n_redundant=5,
            n_clusters_per_class=1,
            weights=[0.95, 0.05],  # 5% fraud rate
            random_state=42
        )
        
        # Create meaningful feature names
        feature_names = [
            'transaction_amount', 'account_age_days', 'num_transactions_today',
            'avg_transaction_amount', 'time_since_last_transaction',
            'merchant_risk_score', 'location_risk_score', 'device_risk_score',
            'velocity_score', 'amount_deviation', 'hour_of_day',
            'day_of_week', 'is_weekend', 'cross_border', 'high_risk_merchant'
        ]
        
        # Transform features to realistic ranges
        X[:, 0] = np.abs(X[:, 0]) * 1000 + 10  # transaction_amount: $10-$5000
        X[:, 1] = np.abs(X[:, 1]) * 365 + 1    # account_age_days: 1-365 days
        X[:, 2] = np.abs(X[:, 2]) * 10 + 1     # num_transactions_today: 1-10
        X[:, 10] = (X[:, 10] % 24 + 24) % 24   # hour_of_day: 0-23
        X[:, 11] = (X[:, 11] % 7 + 7) % 7      # day_of_week: 0-6
        X[:, 12] = (X[:, 12] > 0).astype(int)  # is_weekend: 0 or 1
        X[:, 13] = (X[:, 13] > 0).astype(int)  # cross_border: 0 or 1
        X[:, 14] = (X[:, 14] > 0).astype(int)  # high_risk_merchant: 0 or 1
        
        df = pd.DataFrame(X, columns=feature_names)
        df['is_fraud'] = y
        
        return df
    
    
    def train_models(self, df):
        """Train both Random Forest and SVM models"""
        # Prepare features (exclude target variable)
        feature_columns = [col for col in df.columns if col != 'is_fraud']
        X = df[feature_columns]
        y = df['is_fraud']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Random Forest
        print("Training Random Forest model...")
        self.rf_model.fit(X_train_scaled, y_train)
        rf_pred = self.rf_model.predict(X_test_scaled)
        rf_accuracy = accuracy_score(y_test, rf_pred)
        
        # Train SVM
        print("Training SVM model...")
        self.svm_model.fit(X_train_scaled, y_train)
        svm_pred = self.svm_model.predict(X_test_scaled)
        svm_accuracy = accuracy_score(y_test, svm_pred)
        
        self.is_trained = True
        self.feature_columns = feature_columns
        
        # Print results
        print(f"\nRandom Forest Accuracy: {rf_accuracy:.4f}")
        print(f"SVM Accuracy: {svm_accuracy:.4f}")
        
        print("\nRandom Forest Classification Report:")
        print(classification_report(y_test, rf_pred))
        
        print("\nSVM Classification Report:")
        print(classification_report(y_test, svm_pred))
        
        # Feature importance for Random Forest
        feature_importance = pd.DataFrame({
            'feature': feature_columns,
            'importance': self.rf_model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print("\nTop 10 Most Important Features (Random Forest):")
        print(feature_importance.head(10))
        
        return {
            'rf_accuracy': rf_accuracy,
            'svm_accuracy': svm_accuracy,
            'feature_importance': feature_importance.to_dict('records')
        }
    
    def predict_fraud(self, transaction_data, model_type='ensemble'):
        """Predict fraud probability for a single transaction"""
        if not self.is_trained:
            raise ValueError("Models must be trained before making predictions")
        
        # Ensure transaction_data has all required features
        transaction_df = pd.DataFrame([transaction_data])
        
        # Add missing features with default values if needed
        for col in self.feature_columns:
            if col not in transaction_df.columns:
                transaction_df[col] = 0
        
        # Reorder columns to match training data
        transaction_df = transaction_df[self.feature_columns]
        
        # Scale features
        transaction_scaled = self.scaler.transform(transaction_df)
        
        if model_type == 'rf':
            fraud_prob = self.rf_model.predict_proba(transaction_scaled)[0][1]
            prediction = self.rf_model.predict(transaction_scaled)[0]
        elif model_type == 'svm':
            fraud_prob = self.svm_model.predict_proba(transaction_scaled)[0][1]
            prediction = self.svm_model.predict(transaction_scaled)[0]
        else:  # ensemble
            rf_prob = self.rf_model.predict_proba(transaction_scaled)[0][1]
            svm_prob = self.svm_model.predict_proba(transaction_scaled)[0][1]
            fraud_prob = (rf_prob + svm_prob) / 2
            prediction = 1 if fraud_prob > 0.5 else 0
        
        return {
            'is_fraud': bool(prediction),
            'fraud_probability': float(fraud_prob),
            'risk_level': self._get_risk_level(fraud_prob),
            'timestamp': datetime.now().isoformat()
        }
    
    def _get_risk_level(self, probability):
        """Convert probability to risk level"""
        if probability < 0.3:
            return 'Low'
        elif probability < 0.7:
            return 'Medium'
        else:
            return 'High'
    
    def save_models(self, filepath_prefix='fraud_model'):
        """Save trained models and scaler"""
        if not self.is_trained:
            raise ValueError("Models must be trained before saving")
        
        joblib.dump(self.rf_model, f'{filepath_prefix}_rf.pkl')
        joblib.dump(self.svm_model, f'{filepath_prefix}_svm.pkl')
        joblib.dump(self.scaler, f'{filepath_prefix}_scaler.pkl')
        
        # Save feature columns
        with open(f'{filepath_prefix}_features.json', 'w') as f:
            json.dump(self.feature_columns, f)
        
        print(f"Models saved with prefix: {filepath_prefix}")
    
    def load_models(self, filepath_prefix='fraud_model'):
        """Load trained models and scaler"""
        try:
            self.rf_model = joblib.load(f'{filepath_prefix}_rf.pkl')
            self.svm_model = joblib.load(f'{filepath_prefix}_svm.pkl')
            self.scaler = joblib.load(f'{filepath_prefix}_scaler.pkl')
            
            with open(f'{filepath_prefix}_features.json', 'r') as f:
                self.feature_columns = json.load(f)
            
            self.is_trained = True
            print(f"Models loaded from: {filepath_prefix}")
        except FileNotFoundError as e:
            print(f"Model files not found: {e}")

# Demonstration
if __name__ == "__main__":
    # Initialize the fraud detection system
    fraud_detector = FraudDetectionModel()
    
    # Generate synthetic data
    print("Generating synthetic transaction data...")
    df = fraud_detector.generate_synthetic_data(n_samples=10000)
    
    # Add behavioral biometric features
    
    
    print(f"Dataset shape: {df.shape}")
    print(f"Fraud rate: {df['is_fraud'].mean():.2%}")
    
    # Train models
    results = fraud_detector.train_models(df)
    
    # Test prediction on a sample transaction
    sample_transaction = {
        'transaction_amount': 1500.0,
        'account_age_days': 30,
        'num_transactions_today': 5,
        'avg_transaction_amount': 200.0,
        'time_since_last_transaction': 120,
        'merchant_risk_score': 0.7,
        'location_risk_score': 0.3,
        'device_risk_score': 0.2,
        'velocity_score': 0.8,
        'amount_deviation': 2.5,
        'hour_of_day': 23,
        'day_of_week': 6,
        'is_weekend': 1,
        'cross_border': 1,
        'high_risk_merchant': 1
    }
    
    print("\nTesting fraud detection on sample transaction:")
    prediction = fraud_detector.predict_fraud(sample_transaction)
    print(f"Fraud Prediction: {prediction}")
    
    # Save models for use in Flask app
    fraud_detector.save_models()
    print("\nModels saved successfully!")
