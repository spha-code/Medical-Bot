# Security Implementation for Medical Bot

## Overview
This document describes the security measures implemented to protect the Medical Bot application, ensuring HIPAA compliance and secure handling of medical data.

## Security Features Implemented

### 1. Environment Variables Management
**File**: `.env.example`
- Created template for required environment variables
- Documents all configuration needed for production
- Prevents accidental commit of sensitive credentials

### 2. Rate Limiting
**Implementation**: `app.py` - `RateLimiter` class
- Limits requests to 60 per minute per IP address
- Returns `Retry-After` header when rate limited
- Prevents DDoS and brute-force attacks
- In production, configure Redis storage for distributed limiting

### 3. Input Sanitization
**Implementation**: `app.py` - `InputSanitizer` class
- Sanitizes all user inputs before processing
- Prevents XSS attacks by removing script tags
- Blocks JavaScript protocol in URLs
- Removes event handlers (onclick, onerror, etc.)
- Prevents SQL injection by sanitizing special characters
- Limits input length to prevent DoS
- Special medical query validation (minimum length, max 2000 chars)

### 4. Authentication System
**Implementation**: `app.py`
- **API Key Authentication**: `@require_api_key` decorator
  - Supports header-based authentication (`X-API-Key`)
  - Constant-time comparison to prevent timing attacks
  
- **JWT Token Authentication**: `@require_auth` decorator
  - HMAC-SHA256 signed tokens
  - Configurable expiration (default: 1 hour)
  - Token generation endpoint: `/api/v1/auth/token`

### 5. Secure HTTP Headers
**Implementation**: `app.py` - `add_security_headers()` function
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000`
- `Content-Security-Policy`
- `Referrer-Policy`
- `Permissions-Policy`

### 6. Host Validation
**Implementation**: `app.py` - `before_request()` hook
- Validates `Host` header against allowed hosts
- Prevents host header injection attacks
- Configurable via `ALLOWED_HOSTS` environment variable

### 7. Audit Logging
**Implementation**: `app.py` - `log_audit_event()` function
- Logs all security-relevant events
- Tracks: authentication attempts, queries, errors, rate limits
- Stores timestamp, user_id, IP address, endpoint, details
- Required for HIPAA compliance

### 8. Content Length Limits
**Implementation**: `app.config['MAX_CONTENT_LENGTH']`
- Limits request body to 16MB
- Prevents large payload DoS attacks

## API Endpoints

### Public Endpoints
- `GET /health` - Health check (no auth required)
- `POST /api/v1/auth/token` - Get JWT token

### Protected Endpoints
- `POST /api/v1/query` - Requires API key
- `GET /api/v1/audit/log` - Requires JWT token

## Environment Variables Required

```bash
# Required for production
SECRET_KEY=<32+ character random string>
JWT_SECRET_KEY=<32+ character random string>
API_KEY=<your API key for external access>
OPENAI_API_KEY=<OpenAI API key>
PINECONE_API_KEY=<Pinecone API key>

# Security settings
ALLOWED_HOSTS=localhost,127.0.0.1,yourdomain.com
FLASK_ENV=production

# Optional (for distributed rate limiting)
RATELIMIT_STORAGE_URL=redis://localhost:6379
```

## HIPAA Compliance Considerations

### Data Protection
- All API keys stored in environment variables, not in code
- JWT tokens expire after 1 hour
- Audit logging for all access attempts
- Input sanitization prevents injection attacks

### Network Security
- HTTPS required in production (configure reverse proxy)
- CORS configured to allow only trusted origins
- Rate limiting prevents abuse

### Access Control
- Two-tier authentication (API key + JWT)
- User-specific tokens with audit trail
- Host validation prevents spoofing

## Testing Security Measures

### Test Rate Limiting
```bash
# Should be rate limited after 60 requests
for i in {1..65}; do curl http://localhost:5000/health; done
```

### Test Input Sanitization
```bash
curl -X POST http://localhost:5000/api/v1/query \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"query": "<script>alert(1)</script>"}'
# Should sanitize the input
```

### Test Authentication
```bash
# Should fail without API key
curl http://localhost:5000/api/v1/query

# Should work with valid API key
curl -X POST http://localhost:5000/api/v1/query \
  -H "X-API-Key: your-api-key" \
  -d '{"query": "What are symptoms of flu?"}'
```

## Production Deployment Checklist

- [ ] Set all environment variables in secrets manager
- [ ] Configure HTTPS/TLS with valid certificate
- [ ] Set up reverse proxy (nginx/Apache)
- [ ] Configure Redis for distributed rate limiting
- [ ] Set up log aggregation and monitoring
- [ ] Configure CORS for production domains
- [ ] Enable audit log persistence
- [ ] Set up alerts for security events
- [ ] Conduct penetration testing
- [ ] Review and update security policies

## Dependencies Added

```toml
flask-limiter>=3.12  # Rate limiting
cryptography>=44.0.0  # Encryption utilities
```

## References

- [OWASP Flask Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Flask_Cheat_Sheet.html)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [CWE-79: Cross-site Scripting (XSS)](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
