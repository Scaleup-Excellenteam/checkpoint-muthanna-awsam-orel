"""Client IP reputation checks backed by VirusTotal when configured."""

import ipaddress
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


logger = logging.getLogger(__name__)
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"


@dataclass(frozen=True)
class ReputationDecision:
    verdict: str
    reason: str
    malicious: int = 0
    suspicious: int = 0
    reputation: int = 0

    @property
    def allowed(self):
        return self.verdict != "BLOCK"

    def client_message(self):
        return f"[ANTI-BOT] {self.verdict}: {self.reason}"


class VirusTotalChecker:
    def __init__(
        self,
        api_key=None,
        timeout=3,
        cache_seconds=600,
        clock=time.time,
        opener=urllib.request.urlopen,
    ):
        self.api_key = api_key if api_key is not None else os.getenv("VIRUSTOTAL_API_KEY")
        self.timeout = timeout
        self.cache_seconds = cache_seconds
        self.clock = clock
        self.opener = opener
        self.cache = {}
        self.lock = threading.Lock()

    @property
    def status(self):
        return "configured" if self.api_key else "not_configured"

    def check(self, address):
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return self.unknown("invalid client IP address")

        if ip.is_private or ip.is_loopback:
            return ReputationDecision("ALLOW", "local/private address")
        if not self.api_key:
            return self.unknown("VirusTotal API key is not configured")

        cached = self.get_cached(str(ip))
        if cached is not None:
            logger.info("event=anti_bot_cache ip=%s verdict=%s", ip, cached.verdict)
            return cached

        try:
            decision = self.request_report(str(ip))
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            logger.warning("event=anti_bot_error ip=%s error=%s", ip, type(error).__name__)
            decision = self.unknown(f"VirusTotal unavailable ({type(error).__name__})")
        self.set_cached(str(ip), decision)
        return decision

    def request_report(self, address):
        encoded_address = urllib.parse.quote(address, safe=":")
        request = urllib.request.Request(
            VIRUSTOTAL_URL.format(encoded_address),
            headers={"x-apikey": self.api_key, "Accept": "application/json"},
        )
        try:
            with self.opener(request, timeout=self.timeout) as response:
                report = json.load(response)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return self.unknown("VirusTotal has no report for this IP")
            raise

        attributes = report["data"]["attributes"]
        stats = attributes["last_analysis_stats"]
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        reputation = int(attributes.get("reputation", 0))
        verdict = "BLOCK" if malicious > 0 else "ALLOW"
        reason = (
            f"VirusTotal malicious={malicious}, suspicious={suspicious}, "
            f"reputation={reputation}"
        )
        return ReputationDecision(verdict, reason, malicious, suspicious, reputation)

    def get_cached(self, address):
        with self.lock:
            cached = self.cache.get(address)
            if cached is None:
                return None
            stored_at, decision = cached
            if self.clock() - stored_at >= self.cache_seconds:
                del self.cache[address]
                return None
            return decision

    def set_cached(self, address, decision):
        with self.lock:
            self.cache[address] = self.clock(), decision

    @staticmethod
    def unknown(reason):
        return ReputationDecision("UNKNOWN", reason)
