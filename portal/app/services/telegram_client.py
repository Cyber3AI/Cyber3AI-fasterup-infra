"""Telegram Bot API client — minimal wrapper."""
import os
import logging
import requests
from typing import Dict, Any, Optional

log = logging.getLogger(__name__)


class TelegramClient:
    def __init__(self, token: str):
        self.token = token
        self.base_url = f'https://api.telegram.org/bot{token}'

    def get_me(self) -> Dict[str, Any]:
        r = requests.get(f'{self.base_url}/getMe', timeout=5)
        r.raise_for_status()
        return r.json()


_client: Optional[TelegramClient] = None


def get_client() -> TelegramClient:
    global _client
    if _client is None:
        _client = TelegramClient(os.getenv('TELEGRAM_BOT_TOKEN', ''))
    return _client
