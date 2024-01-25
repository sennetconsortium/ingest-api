import json
from typing import Optional

from pymemcache.client.base import PooledClient

MEMCACHED_TTL = 7200

GROUPS_TOKEN_PLACEHOLDER = "<GROUPS_TOKEN>"


class VitessceConfigCache:
    """Memcached wrapper for Vitessce configuration."""

    def __init__(self, memcached_client: PooledClient, memcached_prefix: str):
        self._memcached_client = memcached_client
        self._memcached_prefix = f"{memcached_prefix}_vitessce"

    def get(self, uuid: str, groups_token: str, as_str: bool = False) -> Optional[dict]:
        config_str = self._memcached_client.get(f"{self._memcached_prefix}_{uuid}")
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

        self._memcached_client.set(
            f"{self._memcached_prefix}_{uuid}", config_str, expire=MEMCACHED_TTL
        )

    def delete(self, uuid: str) -> bool:
        return self._memcached_client.delete(
            f"{self._memcached_prefix}_{uuid}", noreply=False
        )

    def _should_cache(self, config: dict, groups_token: str) -> bool:
        # Don't cache if the config contains the groups token
        return groups_token not in json.dumps(config, separators=(",", ":"))
