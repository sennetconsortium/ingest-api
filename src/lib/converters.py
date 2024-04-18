from werkzeug.routing import BaseConverter


class EntityUUIDConverter(BaseConverter):
    """This converter only accepts entity UUID-like strings; lowercase and no dashes.

    Rule('/object/<entity_uuid:identifier>')
    """

    regex = r"^[a-f0-9]{32}$"

    def to_python(self, value: str) -> str:
        return value

    def to_url(self, value: str) -> str:
        return value
