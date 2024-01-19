import json
from typing import Optional

from pymemcache.client.base import PooledClient

MEMCACHED_TTL = 7200


class VitessceConfigCache:
    """Memcached wrapper for Vitessce configuration."""

    def __init__(self, memcached_client: PooledClient, memcached_prefix: str):
        self._memcached_client = memcached_client
        self._memcached_prefix = f"{memcached_prefix}_vitessce"

    def get(self, uuid) -> Optional[str]:
        return self._memcached_client.get(f"{self._memcached_prefix}_{uuid}")

    def set(self, uuid: str, config: dict, groups_token: str):
        if self._should_cache(config, groups_token):
            self._memcached_client.set(
                f"{self._memcached_prefix}_{uuid}", config, expire=MEMCACHED_TTL
            )

    def delete(self, uuid: str) -> bool:
        return self._memcached_client.delete(
            f"{self._memcached_prefix}_{uuid}", noreply=False
        )

    def _should_cache(self, config: dict, groups_token: str) -> bool:
        # Don't cache if the config contains the groups token
        return groups_token not in json.dumps(config, separators=(",", ":"))
