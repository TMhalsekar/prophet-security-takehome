from sqlalchemy import create_engine, MetaData
from databases import Database

import os

# Check environment
PATH = "/.dockerenv"

if os.path.exists(PATH):
    DATABASE_URL = os.getenv("DATABASE_URL")    #if running inside docker
else:
    DATABASE_URL = "postgresql://postgres:postgres@localhost/suspicious_events"   #running locally

if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is not set")

# Create SQLAlchemy engine for synchronous operations
engine = create_engine(DATABASE_URL)

# Create metadata instance to hold table definitions
metadata = MetaData()

# Set up an async database connection for FastAPI
database = Database(DATABASE_URL)


# Functions to connect and disconnect from the database
async def connect_db():
    await database.connect()


async def disconnect_db():
    await database.disconnect()
