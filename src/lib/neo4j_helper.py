from typing import List

from neo4j import Driver, Record

neo4j_driver_instance = None


class Neo4jHelper:
    @staticmethod
    def set_instance(neo4j):
        global neo4j_driver_instance
        neo4j_driver_instance = neo4j

    @staticmethod
    def get_instance():
        global neo4j_driver_instance
        return neo4j_driver_instance

    @staticmethod
    def close():
        # Specify as module-scope variable
        global neo4j_driver_instance

        if isinstance(neo4j_driver_instance, Driver):
            neo4j_driver_instance.close()
            neo4j_driver_instance = None
        else:
            raise TypeError(
                "The private module variable '_driver' is not a neo4j.Driver object"
            )

    @staticmethod
    def run_query(query, as_dict: bool = False, **kwargs) -> List[Record]:
        if not isinstance(neo4j_driver_instance, Driver):
            raise TypeError(
                "The private module variable '_driver' is not a neo4j.Driver object"
            )

        with neo4j_driver_instance.session() as session:
            result = session.run(query, **kwargs)
            if as_dict:
                return result.data()
            return [Record(record) for record in result]
