# AI-Powered Fraud Detection System - Setup Guide

## 🚀 Quick Start

### 1. Install Dependencies
\`\`\`bash
pip install flask pandas numpy scikit-learn joblib sqlite3 stripe requests aiohttp
\`\`\`

### 2. Basic Setup
\`\`\`bash
# Clone or download the project
cd fraud-detection-system

# Run the application
python app.py
\`\`\`

The system will automatically:
- Create necessary databases
- Train ML models on synthetic data
- Start the web interface on http://localhost:5000

## 🔌 Payment Processor Integration

### Stripe Integration

1. **Get Stripe API Keys**
   - Sign up at https://stripe.com
   - Get your Secret Key from the Dashboard

2. **Set Environment Variables**
   \`\`\`bash
   export STRIPE_SECRET_KEY="sk_test_your_secret_key"
   export STRIPE_WEBHOOK_SECRET="whsec_your_webhook_secret"
   \`\`\`

3. **Configure Webhooks**
   - In Stripe Dashboard, go to Webhooks
   - Add endpoint: `https://yourdomain.com/webhooks/stripe`
   - Select events: `charge.succeeded`, `charge.failed`, `charge.dispute.created`

### PayPal Integration

1. **Get PayPal API Credentials**
   - Sign up at https://developer.paypal.com
   - Create an app to get Client ID and Secret

2. **Set Environment Variables**
   \`\`\`bash
   export PAYPAL_CLIENT_ID="your_client_id"
   export PAYPAL_CLIENT_SECRET="your_client_secret"
   export PAYPAL_SANDBOX="true"  # Set to false for production
   \`\`\`

## 🛡️ Fraud Database Integration

### MaxMind minFraud

1. **Sign up for MaxMind**
   - Create account at https://www.maxmind.com/en/solutions/minfraud-services
   - Get Account ID and License Key

2. **Set Environment Variables**
   \`\`\`bash
   export MAXMIND_ACCOUNT_ID="your_account_id"
   export MAXMIND_LICENSE_KEY="your_license_key"
   \`\`\`

### Sift Integration

1. **Sign up for Sift**
   - Create account at https://sift.com
   - Get API Key from console

2. **Set Environment Variables**
   \`\`\`bash
   export SIFT_API_KEY="your_api_key"
   \`\`\`

## ⚙️ Advanced Configuration

### Real-time Processing
\`\`\`bash
export ENABLE_REAL_TIME_PROCESSING="true"
export MAX_PROCESSING_THREADS="5"
export BATCH_SIZE="10"
\`\`\`

### Risk Thresholds
\`\`\`bash
export LOW_RISK_THRESHOLD="0.3"
export HIGH_RISK_THRESHOLD="0.7"
\`\`\`

### Alert Configuration
\`\`\`bash
export FRAUD_ALERT_WEBHOOK_URL="https://your-webhook-url.com"
export FRAUD_ALERT_EMAIL="alerts@yourcompany.com"
export EMAIL_SMTP_SERVER="smtp.gmail.com"
export EMAIL_SMTP_PORT="587"
export EMAIL_USERNAME="your_email@gmail.com"
export EMAIL_PASSWORD="your_app_password"
\`\`\`

## 🔄 Webhook Setup

### Stripe Webhooks
Configure these events in your Stripe Dashboard:
- `charge.succeeded` - Successful payments
- `charge.failed` - Failed payments  
- `charge.dispute.created` - Chargebacks
- `payment_intent.succeeded` - Payment intents

Webhook URL: `https://yourdomain.com/webhooks/stripe`

### PayPal Webhooks
Configure these events in PayPal Developer Console:
- `PAYMENT.CAPTURE.COMPLETED` - Successful payments
- `PAYMENT.CAPTURE.DENIED` - Failed payments

Webhook URL: `https://yourdomain.com/webhooks/paypal`

## 🧪 Testing

### Test the System
1. Visit http://localhost:5000/demo
2. Try the sample transactions
3. Check the results in the dashboard

### Test Webhooks
\`\`\`bash
# Test webhook endpoint
curl -X POST http://localhost:5000/webhooks/test \
  -H "Content-Type: application/json" \
  -d '{
    "test_transaction": {
      "transaction_id": "TEST_001",
      "user_id": "TEST_USER",
      "amount": 150.00,
      "merchant": "Test Store"
    }
  }'
\`\`\`

### Test API
\`\`\`bash
# Test fraud analysis API
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "USER_123",
    "amount": 1500.0,
    "merchant": "Online Store",
    "email": "test@example.com"
  }'
\`\`\`

## 📊 Monitoring

### Dashboard Features
- **Real-time Statistics** - Transaction counts, fraud rates
- **Recent Transactions** - Latest processed transactions
- **Active Alerts** - High-risk transactions requiring attention
- **Integration Status** - Health of external connections

### API Endpoints
- `GET /api/stats` - Get fraud statistics
- `POST /api/analyze` - Analyze single transaction
- `POST /api/sync/stripe` - Manually sync Stripe data

## 🔒 Security Best Practices

1. **Environment Variables**
   - Never commit API keys to version control
   - Use environment variables for all secrets
   - Rotate keys regularly

2. **Webhook Security**
   - Always verify webhook signatures
   - Use HTTPS for webhook endpoints
   - Implement rate limiting

3. **Database Security**
   - Use encrypted connections
   - Regular backups
   - Access controls

## 🚀 Production Deployment

### Docker Deployment
\`\`\`dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["python", "app.py"]
\`\`\`

### Environment Variables for Production
\`\`\`bash
# Database
export DATABASE_URL="postgresql://user:pass@host:port/dbname"

# Security
export SECRET_KEY="your-secret-key"
export FLASK_ENV="production"

# Scaling
export MAX_PROCESSING_THREADS="10"
export ENABLE_REAL_TIME_PROCESSING="true"
\`\`\`

## 📈 Performance Optimization

### Database Optimization
- Index frequently queried columns
- Use connection pooling
- Regular maintenance

### Processing Optimization
- Adjust thread counts based on CPU cores
- Optimize batch sizes
- Monitor queue sizes

### Caching
- Cache fraud scores for repeat customers
- Cache external API responses
- Use Redis for session storage

## 🆘 Troubleshooting

### Common Issues

1. **"Models not found" error**
   - The system will auto-train models on first run
   - Check write permissions in the directory

2. **Webhook signature verification failed**
   - Verify webhook secrets are correctly set
   - Check endpoint URLs match exactly

3. **External API errors**
   - Verify API keys are valid
   - Check rate limits
   - Monitor API status pages

### Logs
Check the application logs for detailed error information:
\`\`\`bash
tail -f fraud_detection.log
\`\`\`

## 📞 Support

For issues or questions:
1. Check the troubleshooting section
2. Review the logs for error details
3. Test with the demo transactions first
4. Verify all environment variables are set correctly
