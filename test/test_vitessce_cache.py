import json
from unittest.mock import patch

from redis.client import Redis

from lib.vitessce import VitessceConfigCache


def test_set_strips_token():
    """Test that the cache strips the groups token from the config before caching"""

    with patch.object(Redis, "set", return_value=None) as mock_set:
        client = Redis("test_host")
        cache = VitessceConfigCache(client)
        config = {"test": "token=SUPERSECRET"}

        cache.set("test_uuid", config, "SUPERSECRET")

        mock_set.assert_called_once()
        assert mock_set.call_args.args[1] == '{"test":"token=<GROUPS_TOKEN>"}'


def test_get_populates_token():
    """Test that the cache populates the groups token in the config after retrieving"""

    mock_return = json.dumps({"test": "token=<GROUPS_TOKEN>"}, separators=(",", ":"))
    with patch.object(Redis, "get", return_value=mock_return) as mock_get:
        client = Redis("test_host")
        cache = VitessceConfigCache(client)

        config = cache.get("test_uuid", "SUPERSECRET", as_str=True)

        config = json.loads(config)
        mock_get.assert_called_once()
        assert config["test"] == "token=SUPERSECRET"
