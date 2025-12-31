from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # Authentification
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Google OAuth
    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str
    # AJOUTEZ CETTE LIGNE (doit être en MAJUSCULES comme dans votre .env)
    GOOGLE_REDIRECT_URI: str 
    
    # Base de données PostgreSQL
    # AJOUTEZ CETTE LIGNE
    DATABASE_URL: str

    # SMTP
    SMTP_HOST: str
    SMTP_PORT: int
    SMTP_USERNAME: str
    SMTP_PASSWORD: str
    SMTP_FROM: str

    FRONTEND_URL: str


    model_config = SettingsConfigDict(
        env_file=".env", 
        extra="ignore"  # CECI RÉSOUT L'ERREUR "Extra inputs are not permitted"
    )