import os
import re
import hashlib
import hmac
import time
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, g
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", os.urandom(32))
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", os.urandom(32))
app.config["API_KEY"] = os.getenv("API_KEY", None)
app.config["ALLOWED_HOSTS"] = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(
    ","
)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

AUDIT_LOG = []


def log_audit_event(event_type: str, user_id: str = None, details: str = None):
    """Log security-relevant events for compliance"""
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "user_id": user_id,
        "ip_address": request.remote_addr,
        "endpoint": request.path,
        "details": details,
    }
    AUDIT_LOG.append(event)
    logger.info(f"AUDIT: {event_type} - {details}")


class RateLimiter:
    def __init__(self):
        self.requests = {}
        self.window_seconds = 60
        self.max_requests = 60

    def is_rate_limited(self, identifier: str) -> tuple[bool, int]:
        current_time = time.time()
        if identifier not in self.requests:
            self.requests[identifier] = []

        window_start = current_time - self.window_seconds
        self.requests[identifier] = [
            t for t in self.requests[identifier] if t > window_start
        ]

        if len(self.requests[identifier]) >= self.max_requests:
            retry_after = int(self.requests[identifier][0] - window_start + 1)
            return True, retry_after

        self.requests[identifier].append(current_time)
        return False, 0


rate_limiter = RateLimiter()


def check_rate_limit(identifier: str):
    limited, retry_after = rate_limiter.is_rate_limited(identifier)
    if limited:
        log_audit_event("RATE_LIMIT_EXCEEDED", details=f"Retry after {retry_after}s")
        return jsonify(
            {"error": "Rate limit exceeded", "retry_after": retry_after}
        ), 429
    return None


class InputSanitizer:
    @staticmethod
    def sanitize_text(text: str, max_length: int = 10000) -> str:
        if not isinstance(text, str):
            return ""
        text = text.strip()[:max_length]
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
        text = re.sub(
            r"<script[^>]*>.*?</script>", "", text, flags=re.IGNORECASE | re.DOTALL
        )
        text = re.sub(r"javascript:", "", text, flags=re.IGNORECASE)
        text = re.sub(r"on\w+\s*=", "", text, flags=re.IGNORECASE)
        text = re.sub(
            r"<iframe[^>]*>.*?</iframe>", "", text, flags=re.IGNORECASE | re.DOTALL
        )
        text = re.sub(r"--.*?(?:--|$)", "", text)
        text = re.sub(
            r"'\s*(?:OR|AND|SELECT|UNION|DROP|DELETE|UPDATE|INSERT).*?",
            "",
            text,
            flags=re.IGNORECASE,
        )
        return text

    @staticmethod
    def sanitize_medical_query(query: str) -> str:
        sanitized = InputSanitizer.sanitize_text(query, max_length=2000)
        if len(sanitized) < 2:
            raise ValueError("Query too short after sanitization")
        return sanitized


sanitizer = InputSanitizer()


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
        expected_key = app.config["API_KEY"]

        if expected_key is None:
            return jsonify({"error": "API key not configured"}), 500

        if not api_key or not hmac.compare_digest(api_key, expected_key):
            log_audit_event("AUTH_FAILED", details="Invalid API key attempt")
            return jsonify({"error": "Invalid API key"}), 401

        return f(*args, **kwargs)

    return decorated


def generate_jwt_token(user_id: str, expires_delta: timedelta = None) -> str:
    if expires_delta is None:
        expires_delta = timedelta(hours=1)

    expiry = datetime.utcnow() + expires_delta
    payload = {"user_id": user_id, "exp": expiry, "iat": datetime.utcnow()}

    import base64

    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode()
    payload_b64 = base64.urlsafe_b64encode(str(payload).encode()).decode()
    signature = hmac.new(
        app.config["JWT_SECRET_KEY"].encode(),
        f"{header}.{payload_b64}".encode(),
        hashlib.sha256,
    ).hexdigest()

    return f"{header}.{payload_b64}.{signature}"


def verify_jwt_token(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header, payload_b64, signature = parts
        expected_signature = hmac.new(
            app.config["JWT_SECRET_KEY"].encode(),
            f"{header}.{payload_b64}".encode(),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_signature):
            return None

        import base64

        payload = eval(base64.urlsafe_b64decode(payload_b64).decode())

        if datetime.utcfromtimestamp(payload["exp"]) < datetime.utcnow():
            return None

        return payload
    except Exception:
        return None


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            log_audit_event("AUTH_FAILED", details="Missing Bearer token")
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header[7:]
        payload = verify_jwt_token(token)

        if not payload:
            log_audit_event("AUTH_FAILED", details="Invalid or expired token")
            return jsonify({"error": "Invalid or expired token"}), 401

        g.user_id = payload["user_id"]
        return f(*args, **kwargs)

    return decorated


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


@app.before_request
def before_request():
    if request.remote_addr:
        rate_limit_result = check_rate_limit(request.remote_addr)
        if rate_limit_result:
            return rate_limit_result

    if request.host not in app.config["ALLOWED_HOSTS"]:
        log_audit_event("HOST_INVALID", details=f"Invalid host: {request.host}")
        return jsonify({"error": "Host not allowed"}), 403


@app.errorhandler(404)
def not_found(error):
    log_audit_event("PAGE_NOT_FOUND", details=request.path)
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    log_audit_event("INTERNAL_ERROR", details=str(error))
    return jsonify({"error": "Internal server error"}), 500


@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})


@app.route("/api/v1/query", methods=["POST"])
@require_api_key
def query_medical_bot():
    try:
        data = request.get_json()
        if not data or "query" not in data:
            return jsonify({"error": "Missing query parameter"}), 400

        sanitized_query = sanitizer.sanitize_medical_query(data["query"])

        log_audit_event(
            "QUERY_EXECUTED",
            user_id=g.get("user_id"),
            details=f"Query length: {len(sanitized_query)}",
        )

        response = {
            "status": "success",
            "query": sanitized_query,
            "result": f"Response to: {sanitized_query}",
            "timestamp": datetime.utcnow().isoformat(),
        }

        return jsonify(response)

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        log_audit_event("QUERY_ERROR", details=str(e))
        return jsonify({"error": "Processing error"}), 500


@app.route("/api/v1/auth/token", methods=["POST"])
def get_auth_token():
    try:
        data = request.get_json()
        if not data or "user_id" not in data:
            return jsonify({"error": "Missing user_id"}), 400

        user_id = sanitizer.sanitize_text(data["user_id"], max_length=100)
        token = generate_jwt_token(user_id)

        log_audit_event("TOKEN_GENERATED", user_id=user_id)

        return jsonify({"token": token, "expires_in": 3600, "token_type": "Bearer"})

    except Exception as e:
        log_audit_event("AUTH_ERROR", details=str(e))
        return jsonify({"error": "Authentication error"}), 500


@app.route("/api/v1/audit/log", methods=["GET"])
@require_auth
def get_audit_log():
    return jsonify({"audit_log": AUDIT_LOG[-100:]})


if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV") != "production"

    logger.info(f"Starting Medical Bot with security measures enabled")
    logger.info(f"Environment: {'Production' if not debug else 'Development'}")

    app.run(host=host, port=port, debug=debug)
