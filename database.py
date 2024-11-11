from sqlalchemy import create_engine, MetaData
from databases import Database

import os

# Database URL for PostgreSQL
#DATABASE_URL = "postgresql://postgres:postgres@localhost/suspicious_events"

DATABASE_URL_STRING = os.getenv("DATABASE_URL")

if not DATABASE_URL_STRING:
    raise ValueError("DATABASE_URL environment variable is not set")

# Create SQLAlchemy engine for synchronous operations
engine = create_engine(DATABASE_URL_STRING)

# Create metadata instance to hold table definitions
metadata = MetaData()

# Set up an async database connection for FastAPI
DATABASE_URL = DATABASE_URL_STRING
database = Database(DATABASE_URL)


# Functions to connect and disconnect from the database
async def connect_db():
    await database.connect()


async def disconnect_db():
    await database.disconnect()
