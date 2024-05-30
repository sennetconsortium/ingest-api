import json
from typing import Optional

from redis.client import Redis

REDIS_TTL = 7200

GROUPS_TOKEN_PLACEHOLDER = "<GROUPS_TOKEN>"
REDIS_VITESSCE_PREFIX = "sn_vitessce_"


class VitessceConfigCache:
    """Redis wrapper for Vitessce configuration."""

    def __init__(self, redis_client: Redis):
        self._redis_client = redis_client

    def get(self, uuid: str, groups_token: str, as_str: bool = False) -> Optional[dict]:
        config_str = self._redis_client.get(f"{REDIS_VITESSCE_PREFIX}_{uuid}")
        if config_str is None:
            return None
        if GROUPS_TOKEN_PLACEHOLDER in config_str:
            # Replace the groups token placeholder with the actual groups token
            config_str = config_str.replace(GROUPS_TOKEN_PLACEHOLDER, groups_token)
        if as_str:
            return config_str
        return json.loads(config_str)

    def set(self, uuid: str, config: dict, groups_token: str):
        config_str = json.dumps(config, separators=(",", ":"))
        if groups_token in config_str:
            # Replace the groups token with a placeholder to avoid caching the token
            config_str = config_str.replace(groups_token, GROUPS_TOKEN_PLACEHOLDER)

        self._redis_client.set(
            f"{REDIS_VITESSCE_PREFIX}_{uuid}", config_str, ex=REDIS_TTL
        )

    def delete(self, uuid: str) -> bool:
        return self._redis_client.delete(
            f"{REDIS_VITESSCE_PREFIX}_{uuid}"
        )

    def _should_cache(self, config: dict, groups_token: str) -> bool:
        # Don't cache if the config contains the groups token
        return groups_token not in json.dumps(config, separators=(",", ":"))
