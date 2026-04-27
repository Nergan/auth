import logging
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING
from app.config import settings

class Database:
    client: AsyncIOMotorClient = None
    db = None
    users_collection = None
    used_nonces_collection = None

db_instance = Database()

async def connect_to_mongo():
    logging.info("Connecting to MongoDB...")
    
    # Only pass TLS if explicitly enabled (no tlsAllowInvalidCertificates allowed!)
    kwargs = {}
    if settings.mongo_tls:
        kwargs["tls"] = True

    db_instance.client = AsyncIOMotorClient(settings.mongodb_uri, **kwargs)
    db_instance.db = db_instance.client.asymmetric_auth_db
    
    db_instance.users_collection = db_instance.db.users
    db_instance.used_nonces_collection = db_instance.db.used_nonces

    # Unique index for users
    await db_instance.users_collection.create_index("user_id", unique=True)
    
    # ATOMIC REPLAY PROTECTION: Unique composite index for user_id + nonce
    await db_instance.used_nonces_collection.create_index(
        [("user_id", ASCENDING), ("nonce", ASCENDING)], 
        unique=True
    )
    
    # Auto-cleanup nonces after 5 minutes
    await db_instance.used_nonces_collection.create_index("created_at", expireAfterSeconds=300)
    logging.info("Connected to MongoDB successfully.")

async def close_mongo_connection():
    if db_instance.client:
        db_instance.client.close()
        logging.info("Closed MongoDB connection.")