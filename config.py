import os
basedir = os.path.abspath(os.path.dirname(__file__))
postgres_local_base = 'postgresql://postgres:postgres@localhost:5432/'
database_name = 'flask_todo_app'


class BaseConfig:
    """Base configuration."""
    SECRET_KEY = os.getenv('SECRET_KEY', 'my_precious')
    DEBUG = False
    BCRYPT_LOG_ROUNDS = 13
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class DevelopmentConfig(BaseConfig):
    """Development configuration."""
    DEBUG = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = 'postgresql://fxblfrbesmdfxe:fa9501da8798a8f11347184efa2947d7bf1e9ae262c0358fbc001c106d0bca47@ec2-34-197-249-102.compute-1.amazonaws.com:5432/db35gkiqac5mth'


class ProductionConfig(BaseConfig):
    """Production configuration."""
    SECRET_KEY = 'my_precious'
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'postgresql://fxblfrbesmdfxe:fa9501da8798a8f11347184efa2947d7bf1e9ae262c0358fbc001c106d0bca47@ec2-34-197-249-102.compute-1.amazonaws.com:5432/db35gkiqac5mth'
