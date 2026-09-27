from enum import Enum


class ErrorMessage(str, Enum):
    """Error messages for authentication system"""

    # Client & Auth
    INVALID_CLIENT = "Invalid client credentials"
    INVALID_GRANT = "Invalid or expired grant"
    INVALID_REQUEST = "Invalid request format"
    UNAUTHORIZED_CLIENT = "Client not authorized"
    INVALID_SCOPE = "Invalid scope requested"
    ACCESS_DENIED = "Access denied by resource owner"

    # Common errors
    NOT_FOUND = "Resource not found"
    CONFLICT = "Resource already exists"
    UNAUTHORIZED = "Authentication required"
    RATE_LIMITED = "Too many requests"

    # Verification
    INVALID_OTP = "Invalid or expired verification code"
    EMAIL_NOT_VERIFIED = "Email address has not been verified"

    # Server errors
    SERVER_ERROR = "Internal server error"
    SERVICE_UNAVAILABLE = "Service temporarily unavailable"
