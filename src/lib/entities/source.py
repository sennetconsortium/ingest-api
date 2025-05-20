from hubmap_sdk.entity import Entity


class Source(Entity):
    def __init__(self, instance):
        super().__init__(instance)
        for key in instance:
            setattr(self, key, instance[key])
