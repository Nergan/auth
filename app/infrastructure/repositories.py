from datetime import datetime, timezone, timedelta
import logging
from typing import Optional, Tuple
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.config import settings
from app.domain.models import UserEntity, KeyAlgorithm
from app.domain.ports import UserRepositoryPort, NonceManagerPort
from app.domain.anti_replay import evaluate_sliding_replay_window
from app.domain.exceptions import UserAlreadyExistsError
from app.infrastructure.database import db_instance

logger = logging.getLogger(__name__)
MAX_INT64 = (1 << 63) - 1


class MongoUserRepository(UserRepositoryPort):
    """MongoDB User Identity State Store Implementation."""

    def __init__(self, collection: Optional[AsyncIOMotorCollection] = None):
        self._collection = collection

    @property
    def collection(self) -> AsyncIOMotorCollection:
        return self._collection if self._collection is not None else db_instance.users_collection

    async def get_user_by_id(self, user_id: str) -> Optional[UserEntity]:
        doc = await self.collection.find_one({"user_id": user_id})
        if not doc:
            return None
        created_at = doc["created_at"]
        if isinstance(created_at, datetime) and created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

        return UserEntity(
            user_id=doc["user_id"],
            public_key=doc["public_key"],
            key_algorithm=KeyAlgorithm(doc["key_algorithm"]),
            nonce_base=doc.get("nonce_base", 0),
            nonce_mask=doc.get("nonce_mask", 0),
            created_at=created_at
        )

    async def create_user(self, user: UserEntity) -> None:
        try:
            await self.collection.insert_one({
                "user_id": user.user_id,
                "public_key": user.public_key,
                "key_algorithm": user.key_algorithm.value,
                "nonce_base": user.nonce_base,
                "nonce_mask": user.nonce_mask,
                "created_at": user.created_at
            })
        except DuplicateKeyError as exc:
            raise UserAlreadyExistsError("Public key already registered") from exc


class MongoNonceManager(NonceManagerPort):
    """
    MongoDB Atomic Sliding Window Counter and Nonce Tracker.
    Evaluates counters against an RFC 6479-compliant sliding window and commits state via CAS.
    """

    def __init__(
        self,
        users_collection: Optional[AsyncIOMotorCollection] = None,
        sync_nonces_collection: Optional[AsyncIOMotorCollection] = None,
        reg_nonces_collection: Optional[AsyncIOMotorCollection] = None,
    ):
        self._users_collection = users_collection
        self._sync_nonces_collection = sync_nonces_collection
        self._reg_nonces_collection = reg_nonces_collection

    @property
    def users_collection(self) -> AsyncIOMotorCollection:
        return self._users_collection or db_instance.users_collection

    @property
    def sync_nonces_collection(self) -> AsyncIOMotorCollection:
        return self._sync_nonces_collection or db_instance.used_sync_nonces_collection

    @property
    def reg_nonces_collection(self) -> AsyncIOMotorCollection:
        return self._reg_nonces_collection or db_instance.used_registration_nonces_collection

    async def record_sync_nonce(self, user_id: str, sync_nonce: str) -> bool:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.sync_nonce_ttl_seconds)
        # Explicit timestamp cutoff check in addition to background TTL sweeps
        existing = await self.sync_nonces_collection.find_one({
            "user_id": user_id,
            "sync_nonce": sync_nonce,
            "created_at": {"$gte": cutoff}
        })
        if existing:
            return False

        try:
            await self.sync_nonces_collection.insert_one({
                "user_id": user_id,
                "sync_nonce": sync_nonce,
                "created_at": datetime.now(timezone.utc)
            })
            return True
        except DuplicateKeyError:
            # Overwrite if previous entry is expired
            res = await self.sync_nonces_collection.find_one_and_update(
                {"user_id": user_id, "sync_nonce": sync_nonce, "created_at": {"$lt": cutoff}},
                {"$set": {"created_at": datetime.now(timezone.utc)}}
            )
            return bool(res)

    async def record_registration_nonce(self, user_id: str, client_nonce: str) -> bool:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.timestamp_tolerance_seconds * 2)
        existing = await self.reg_nonces_collection.find_one({
            "user_id": user_id,
            "client_nonce": client_nonce,
            "created_at": {"$gte": cutoff}
        })
        if existing:
            return False

        try:
            await self.reg_nonces_collection.insert_one({
                "user_id": user_id,
                "client_nonce": client_nonce,
                "created_at": datetime.now(timezone.utc)
            })
            return True
        except DuplicateKeyError:
            res = await self.reg_nonces_collection.find_one_and_update(
                {"user_id": user_id, "client_nonce": client_nonce, "created_at": {"$lt": cutoff}},
                {"$set": {"created_at": datetime.now(timezone.utc)}}
            )
            return bool(res)

    async def remove_registration_nonce(self, user_id: str, client_nonce: str) -> None:
        await self.reg_nonces_collection.delete_one({"user_id": user_id, "client_nonce": client_nonce})

    async def validate_counter(self, user_id: str, presented_counter: int) -> Tuple[bool, int, str]:
        """Pre-handler validation: checks presented counter against active sliding window without mutating DB."""
        if not (1 <= presented_counter <= MAX_INT64):
            return False, 1, "invalid_counter_bounds"

        doc = await self.users_collection.find_one({"user_id": user_id}, projection={"nonce_base": 1, "nonce_mask": 1})
        if not doc:
            return False, 1, "user_not_found"

        current_base = doc.get("nonce_base", 0)
        current_mask = doc.get("nonce_mask", 0)

        is_valid, expected, reason, _, _ = evaluate_sliding_replay_window(
            current_base=current_base,
            current_mask=current_mask,
            presented=presented_counter,
            max_forward_jump=settings.max_counter_window,
            window_size=settings.replay_window_size
        )
        return is_valid, expected, reason

    async def advance_counter(self, user_id: str, presented_counter: int) -> Tuple[bool, int, str]:
        """Post-handler commit: advances the sliding replay window atomically via CAS with retries."""
        if not (1 <= presented_counter <= MAX_INT64):
            return False, 1, "invalid_counter_bounds"

        for _ in range(5):
            doc = await self.users_collection.find_one({"user_id": user_id}, projection={"nonce_base": 1, "nonce_mask": 1})
            if not doc:
                return False, 1, "user_not_found"

            current_base = doc.get("nonce_base", 0)
            current_mask = doc.get("nonce_mask", 0)

            is_valid, expected, reason, new_base, new_mask = evaluate_sliding_replay_window(
                current_base=current_base,
                current_mask=current_mask,
                presented=presented_counter,
                max_forward_jump=settings.max_counter_window,
                window_size=settings.replay_window_size
            )

            if not is_valid:
                return False, expected, reason

            updated = await self.users_collection.find_one_and_update(
                {
                    "user_id": user_id,
                    "nonce_base": current_base,
                    "nonce_mask": current_mask
                },
                {"$set": {"nonce_base": new_base, "nonce_mask": new_mask}},
                return_document=ReturnDocument.AFTER
            )

            if updated:
                return True, new_base + 1, ""

        return False, 1, "concurrency_contention"


user_repository = MongoUserRepository()
nonce_manager = MongoNonceManager()