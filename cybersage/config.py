from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://cybersage:cybersage@localhost:5432/cybersage"
    nvd_api_key: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
