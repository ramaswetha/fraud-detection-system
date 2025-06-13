from fraud_detection_model import FraudDetectionModel
from database import FraudDatabase

# Initialize components
print("Initializing fraud detection system...")
fraud_detector = FraudDetectionModel()
db = FraudDatabase()

# Generate synthetic data and train models
print("Generating synthetic data...")
df = fraud_detector.generate_synthetic_data(n_samples=5000)
print(f"Generated {len(df)} synthetic transactions")

# Note: We're no longer adding behavioral features
# print("Adding behavioral features...")
# df = fraud_detector.add_behavioral_features(df)

print("Training models...")
results = fraud_detector.train_models(df)

print("Saving models...")
fraud_detector.save_models()

print("Done! Models have been trained and saved.")
print(f"Random Forest Accuracy: {results['rf_accuracy']:.4f}")
print(f"SVM Accuracy: {results['svm_accuracy']:.4f}")