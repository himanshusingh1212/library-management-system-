"""Configuration loaded from environment variables / .env — never hardcode credentials."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Azure auth (used by DefaultAzureCredential: env vars, az login, or managed identity)
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""
    azure_subscription_id: str = ""

    # Anthropic
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-5"

    # API
    cors_allowed_origin: str = "http://localhost:5173"
    scan_store_path: str = "./data/scans"

    # Sensitive ports checked by the NSG scanner
    sensitive_ports: list[str] = ["22", "3389", "1433", "3306", "5432", "27017", "6379", "9200"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
