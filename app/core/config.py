from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "Open Sesame! An Authentication Service"
    ENVIRONMENT: str = "development"

    # DATABASE
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_NAME: str
    DB_USER: str
    DB_PASSWORD: str

    # REDIS
    REDIS_URL: str
    REDIS_CACHE_TTL: int = 3600  # seconds

    # JWT
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE: int = 900  # seconds

    # CORS
    BACKEND_CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    # OPTIONAL SETTINGS
    DEBUG: bool = False

    # SESSION
    SESSION_EXPIRE_DAYS: int = 7  # days

    @property
    def database_url(self) -> str:
        return f"postgresql+asyncpg://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    @property
    def session_max_age_seconds(self) -> int:
        return self.SESSION_EXPIRE_DAYS * 86400

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


class EmailConfigSettings(BaseSettings):
    """
    Pydantic model for SMTP server configuration.
    Reads settings from environment variables.
    """

    SMTP_HOST: str
    SMTP_PORT: int = 587
    SMTP_USER: str
    SMTP_PASSWORD: str
    EMAILS_FROM_EMAIL: str
    EMAILS_FROM_NAME: str = "My Application"

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache()
def get_email_settings() -> EmailConfigSettings:
    return EmailConfigSettings()


# Export instance
settings = get_settings()
email_settings = get_email_settings()
