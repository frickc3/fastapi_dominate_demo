# config.py
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache

class Settings(BaseSettings):
	COOKIE_SECURE: bool = True
	DEBUG: bool = False
	SESSION_KEY: str = None
	SESSION_AGE: int = 3600		# 1 hour
	#SESSION_HOURS: int = 12
	RESET_MINUTES: int = 30
	DB_PATH: str = "data"
	DB_NAME: str = "auth.db"
	DB_SECRET: str
	HTTP_PORT: int = 8000
	HTTP_HOST: str = "localhost"

	model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

@lru_cache
def get_settings() -> Settings:
	return Settings()