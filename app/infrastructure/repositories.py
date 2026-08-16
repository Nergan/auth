import asyncio
from datetime import datetime, timezone
import logging
import random
from typing import Optional, Tuple
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.config import settings
from app.domain.models import UserEntity, KeyAlgorithm
from app.domain.ports import UserRepositoryPort, NonceManagerPort
from app.domain.anti_replay import evaluate_sliding_window
from app.domain.exceptions import UserAlreadyExistsError, UnsupportedAlgorithmError
from app.infrastructure.database import db_instance

logger = logging.getLogger(__name__)
MAX_INT64 = (1 << 63) - 1


def mask_to_hex(mask: int) -> str:
    """Serializes integer bitmask to fixed 16-character hex string avoiding BSON int64 overflow."""
    return f"{mask:016x}"


def hex_to_mask(hex_str: Optional[str | int]) -> int:
    """Parses hex string or legacy integer into domain bitmask."""
    if not hex_str:
        return 0
    if isinstance(hex_str, int):
        return hex_str
    try:
        return int(hex_str, 16)
    except ValueError:
        return 0


class MongoUserRepository(UserRepositoryPort):
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

        try:
            key_algorithm = KeyAlgorithm(doc["key_algorithm"])
        except (ValueError, KeyError):
            raise UnsupportedAlgorithmError(str(doc.get("key_algorithm", "unknown")))

        return UserEntity(
            user_id=doc["user_id"],
            public_key=doc["public_key"],
            key_algorithm=key_algorithm,
            nonce_base=doc.get("nonce_base", doc.get("nonce_counter", 0)),
            nonce_mask=hex_to_mask(doc.get("nonce_mask")),
            created_at=created_at
        )

    async def create_user(self, user: UserEntity) -> None:
        try:
            await self.collection.insert_one({
                "user_id": user.user_id,
                "public_key": user.public_key,
                "key_algorithm": user.key_algorithm.value,
                "nonce_base": user.nonce_base,
                "nonce_mask": mask_to_hex(user.nonce_mask),
                "created_at": user.created_at
            })
        except DuplicateKeyError as exc:
            raise UserAlreadyExistsError("Public key already registered") from exc


class MongoNonceManager(NonceManagerPort):
    def __init__(
        self,
        users_collection: Optional[AsyncIOMotorCollection] = None,
        sync_nonces_collection: Optional[AsyncIOMotorCollection] = None,
        reg_nonces_collection: Optional[AsyncIOMotorCollection] = None,
        max_retries: int = 10,
        base_delay: float = 0.005
    ):
        self._users_collection = users_collection
        self._sync_nonces_collection = sync_nonces_collection
        self._reg_nonces_collection = reg_nonces_collection
        self.max_retries = max_retries
        self.base_delay = base_delay

    @property
    def users_collection(self) -> AsyncIOMotorCollection:
        return self._users_collection if self._users_collection is not None else db_instance.users_collection

    @property
    def sync_nonces_collection(self) -> AsyncIOMotorCollection:
        return self._sync_nonces_collection if self._sync_nonces_collection is not None else db_instance.used_sync_nonces_collection

    @property
    def reg_nonces_collection(self) -> AsyncIOMotorCollection:
        return self._reg_nonces_collection if self._reg_nonces_collection is not None else db_instance.used_registration_nonces_collection

    async def record_sync_nonce(self, user_id: str, sync_nonce: str) -> bool:
        try:
            await self.sync_nonces_collection.insert_one({
                "user_id": user_id,
                "sync_nonce": sync_nonce,
                "created_at": datetime.now(timezone.utc)
            })
            return True
        except DuplicateKeyError:
            return False

    async def record_registration_nonce(self, user_id: str, client_nonce: str) -> bool:
        try:
            await self.reg_nonces_collection.insert_one({
                "user_id": user_id,
                "client_nonce": client_nonce,
                "created_at": datetime.now(timezone.utc)
            })
            return True
        except DuplicateKeyError:
            return False

    async def remove_registration_nonce(self, user_id: str, client_nonce: str) -> None:
        try:
            await self.reg_nonces_collection.delete_one({
                "user_id": user_id,
                "client_nonce": client_nonce
            })
        except Exception as exc:
            logger.warning("Failed to remove registration challenge nonce for user %s: %s", user_id, exc)

    @staticmethod
    def _build_cas_filter(user_id: str, current_base: int, current_mask: int) -> dict:
        if current_mask == 0:
            mask_filter = {"$in": [None, mask_to_hex(0), 0]}
        else:
            mask_filter = {"$in": [mask_to_hex(current_mask), current_mask]}

        if current_base == 0:
            return {
                "user_id": user_id,
                "$or": [
                    {"nonce_base": 0, "nonce_mask": mask_filter},
                    {"nonce_base": {"$exists": False}, "nonce_mask": mask_filter},
                ]
            }
        return {
            "user_id": user_id,
            "nonce_base": current_base,
            "nonce_mask": mask_filter
        }

    async def validate_and_advance(
        self,
        user_id: str,
        presented_counter: int,
        current_user: Optional[UserEntity] = None
    ) -> Tuple[bool, int, str]:
        if not (1 <= presented_counter <= MAX_INT64):
            return False, 1, "invalid_counter_bounds"

        for attempt in range(self.max_retries):
            if attempt == 0 and current_user is not None and current_user.user_id == user_id:
                current_base = current_user.nonce_base
                current_mask = current_user.nonce_mask
            else:
                doc = await self.users_collection.find_one(
                    {"user_id": user_id},
                    projection={"nonce_base": 1, "nonce_mask": 1, "nonce_counter": 1}
                )
                if not doc:
                    return False, 1, "user_not_found"

                current_base = doc.get("nonce_base", doc.get("nonce_counter", 0))
                current_mask = hex_to_mask(doc.get("nonce_mask"))

            is_valid, new_base, new_mask, reason = evaluate_sliding_window(
                base=current_base,
                mask=current_mask,
                presented=presented_counter,
                max_forward_window=settings.max_counter_window
            )

            if not is_valid:
                return False, current_base + 1, reason

            query_filter = self._build_cas_filter(user_id, current_base, current_mask)

            updated = await self.users_collection.find_one_and_update(
                query_filter,
                {
                    "$set": {"nonce_base": new_base, "nonce_mask": mask_to_hex(new_mask)},
                    "$unset": {"nonce_counter": ""}
                },
                return_document=ReturnDocument.AFTER
            )
            if updated:
                return True, new_base + 1, ""

            backoff = self.base_delay * (2 ** attempt) + random.uniform(0, 0.01)
            await asyncio.sleep(backoff)

        current_doc = await self.users_collection.find_one({"user_id": user_id})
        expected = (current_doc.get("nonce_base", 0) + 1) if current_doc else 1
        return False, expected, "concurrency_contention"


user_repository = MongoUserRepository()
nonce_manager = MongoNonceManager()