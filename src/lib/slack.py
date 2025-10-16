import requests
from flask import current_app


def send_slack_notification(message: str):
    slack_url = current_app.config.get("SLACK_WEBHOOK_URL")
    if not slack_url:
        raise ValueError("SLACK_WEBHOOK_URL is not configured")

    res = requests.post(slack_url, json={"text": message})
    if not res.ok:
        raise Exception(f"Failed to send Slack notification: {res.text}")
