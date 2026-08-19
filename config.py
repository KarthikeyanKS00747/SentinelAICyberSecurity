"""Environment-backed application configuration."""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings loaded from environment variables and an optional ``.env`` file."""

    APP_NAME: str = "SentinelAI"
    SECRET_KEY: str = Field(default="development-only-change-me", min_length=16)
    OLLAMA_MODEL: str = "llama3"
    MAX_UPLOAD_SIZE_BYTES: int = Field(default=10 * 1024 * 1024, gt=0)
    DB_URL: str = "sqlite+aiosqlite:///./sentinelai.db"
    UPLOAD_DIR: Path = Path("uploads")
    ALLOWED_ORIGINS: list[str] = [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
