import os
from pydantic import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str
    SUPABASE_URL: str
    SUPABASE_KEY: str
    OPENAI_API_KEY: str
    NETWORK_INTERFACE: str = "eth0"

    class Config:
        env_file = ".env"

settings = Settings()
