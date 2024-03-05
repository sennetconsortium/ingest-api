import requests


class SessionHelper(object):

    def __init__(self):
        self.airflow_session = None

    def get(self):
        if self.airflow_session is None:
            self.airflow_session = requests.session()
            return self.airflow_session
