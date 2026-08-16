import logging
from typing import Optional, Any
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorCollection
from pymongo import ASCENDING
from app.config import settings

logger = logging.getLogger(__name__)


class Database:
    client: Optional[AsyncIOMotorClient] = None
    db: Optional[AsyncIOMotorDatabase] = None
    users_collection: Optional[AsyncIOMotorCollection] = None
    used_sync_nonces_collection: Optional[AsyncIOMotorCollection] = None
    used_registration_nonces_collection: Optional[AsyncIOMotorCollection] = None


db_instance = Database()


async def _reconcile_index(collection: AsyncIOMotorCollection, keys: Any, **kwargs) -> None:
    """
    Creates collection index idempotently. Conflicting index options are dropped
    and recreated. Raises exceptions on failure to guarantee critical security constraints.
    """
    try:
        existing_indexes = await collection.list_indexes().to_list(length=100)
        target_keys = dict(keys if isinstance(keys, list) else [(keys, ASCENDING)] if isinstance(keys, str) else [keys])

        for idx in existing_indexes:
            if idx.get("key") == target_keys:
                needs_drop = False
                if "expireAfterSeconds" in kwargs and idx.get("expireAfterSeconds") != kwargs["expireAfterSeconds"]:
                    needs_drop = True
                if "unique" in kwargs and idx.get("unique", False) != kwargs["unique"]:
                    needs_drop = True

                if needs_drop:
                    logger.info("Dropping conflicting index '%s' on collection %s", idx["name"], collection.name)
                    await collection.drop_index(idx["name"])
                break

        await collection.create_index(keys, **kwargs)
    except Exception as exc:
        logger.critical("Fatal error configuring critical index on collection %s: %s", collection.name, exc)
        raise


async def connect_to_mongo() -> None:
    logger.info("Connecting to MongoDB...")
    kwargs = {
        "serverSelectionTimeoutMS": settings.mongo_server_selection_timeout_ms,
        "connectTimeoutMS": settings.mongo_connect_timeout_ms,
        "maxPoolSize": settings.mongo_max_pool_size,
        "minPoolSize": settings.mongo_min_pool_size,
        "maxIdleTimeMS": settings.mongo_max_idle_time_ms,
        "waitQueueTimeoutMS": settings.mongo_wait_queue_timeout_ms,
    }
    if settings.mongo_tls:
        kwargs["tls"] = True

    db_instance.client = AsyncIOMotorClient(settings.mongodb_uri, **kwargs)
    db_instance.db = db_instance.client[settings.mongodb_db_name]
    db_instance.users_collection = db_instance.db.users
    db_instance.used_sync_nonces_collection = db_instance.db.used_sync_nonces
    db_instance.used_registration_nonces_collection = db_instance.db.used_registration_nonces

    await _reconcile_index(db_instance.users_collection, "user_id", unique=True)
    await _reconcile_index(
        db_instance.used_sync_nonces_collection,
        [("user_id", ASCENDING), ("sync_nonce", ASCENDING)],
        unique=True
    )
    await _reconcile_index(
        db_instance.used_sync_nonces_collection,
        "created_at",
        expireAfterSeconds=settings.sync_nonce_ttl_seconds
    )
    await _reconcile_index(
        db_instance.used_registration_nonces_collection,
        [("user_id", ASCENDING), ("client_nonce", ASCENDING)],
        unique=True
    )
    await _reconcile_index(
        db_instance.used_registration_nonces_collection,
        "created_at",
        expireAfterSeconds=settings.timestamp_tolerance_seconds * 2
    )
    logger.info("Connected to MongoDB successfully with indexes reconciled.")


async def close_mongo_connection() -> None:
    if db_instance.client:
        db_instance.client.close()
        db_instance.client = None
        logger.info("Closed MongoDB connection.")