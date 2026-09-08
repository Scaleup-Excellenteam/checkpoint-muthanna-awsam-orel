"""Client IP reputation checks backed by VirusTotal when configured."""

import ipaddress
import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import timedelta
from http import HTTPStatus

from .config import ANTI_BOT, environment_value


logger = logging.getLogger(__name__)
VIRUSTOTAL_URL = ANTI_BOT["api_url"]


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
        timeout=ANTI_BOT["request_timeout_seconds"],
        cache_seconds=timedelta(minutes=ANTI_BOT["cache_minutes"]).total_seconds(),
        clock=time.time,
        opener=urllib.request.urlopen,
    ):
        self.api_key = (
            api_key if api_key is not None else environment_value("VIRUSTOTAL_API_KEY")
        )
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
            
        if getattr(self, "quota_reset_time", 0) > self.clock():
            return self.unknown("VirusTotal quota exceeded (Circuit Breaker active)")

        cached = self.get_cached(str(ip))
        if cached is not None:
            logger.info("event=anti_bot_cache ip=%s verdict=%s", ip, cached.verdict)
            return cached

        try:
            decision = self.request_report(str(ip))
        except urllib.error.HTTPError as error:
            if error.code == HTTPStatus.NOT_FOUND:
                decision = self.unknown("VirusTotal has no report for this IP")
            elif error.code == 429: # Too Many Requests
                self.quota_reset_time = self.clock() + 60 # Backoff for 1 minute
                logger.warning("event=anti_bot_quota_exceeded ip=%s error=429_too_many_requests", ip)
                decision = self.unknown("VirusTotal rate limit exceeded")
            elif error.code in (401, 403): # Quota exceeded or invalid key
                self.quota_reset_time = self.clock() + 3600 # Backoff for 1 hour
                logger.warning("event=anti_bot_auth_error ip=%s error=%s", ip, error.code)
                decision = self.unknown("VirusTotal quota exceeded or auth error")
            else:
                logger.warning("event=anti_bot_error ip=%s error=HTTPError_%s", ip, error.code)
                decision = self.unknown(f"VirusTotal unavailable (HTTPError {error.code})")
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            logger.warning("event=anti_bot_error ip=%s error=%s", ip, type(error).__name__)
            decision = self.unknown(f"VirusTotal unavailable ({type(error).__name__})")
            
        self.set_cached(str(ip), decision)
        return decision

    def request_report(self, address):
        encoded_address = urllib.parse.quote(address, safe=":")
        request = urllib.request.Request(
            VIRUSTOTAL_URL.format(address=encoded_address),
            headers={"x-apikey": self.api_key, "Accept": "application/json"},
        )
        with self.opener(request, timeout=self.timeout) as response:
            report = json.load(response)

        attributes = report["data"]["attributes"]
        stats = attributes["last_analysis_stats"]
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        reputation = int(attributes.get("reputation", 0))
        verdict = (
            "BLOCK"
            if malicious >= ANTI_BOT["malicious_engines_to_block"]
            else "ALLOW"
        )
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

    def check_url(self, url):
        if not self.api_key:
            return self.unknown("VirusTotal API key is not configured")
            
        if getattr(self, "quota_reset_time", 0) > self.clock():
            return self.unknown("VirusTotal quota exceeded (Circuit Breaker active)")

        cache_key = f"url:{url}"
        cached = self.get_cached(cache_key)
        if cached is not None:
            logger.info("event=anti_bot_url_cache url=%s verdict=%s", url, cached.verdict)
            return cached

        import base64
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")
        
        try:
            request = urllib.request.Request(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": self.api_key, "Accept": "application/json"},
            )
            with self.opener(request, timeout=self.timeout) as response:
                report = json.load(response)

            attributes = report["data"]["attributes"]
            stats = attributes["last_analysis_stats"]
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            reputation = int(attributes.get("reputation", 0))
            
            verdict = (
                "BLOCK"
                if malicious >= ANTI_BOT["malicious_engines_to_block"]
                else "ALLOW"
            )
            reason = (
                f"VirusTotal URL malicious={malicious}, suspicious={suspicious}, "
                f"reputation={reputation}"
            )
            decision = ReputationDecision(verdict, reason, malicious, suspicious, reputation)
        except urllib.error.HTTPError as error:
            if error.code == HTTPStatus.NOT_FOUND:
                decision = self.unknown("VirusTotal has no report for this URL")
            elif error.code == 429:
                self.quota_reset_time = self.clock() + 60
                logger.warning("event=anti_bot_quota_exceeded url=%s error=429", url)
                decision = self.unknown("VirusTotal rate limit exceeded")
            elif error.code in (401, 403):
                self.quota_reset_time = self.clock() + 3600
                logger.warning("event=anti_bot_auth_error url=%s error=%s", url, error.code)
                decision = self.unknown("VirusTotal quota exceeded or auth error")
            else:
                logger.warning("event=anti_bot_error url=%s error=HTTPError_%s", url, error.code)
                decision = self.unknown(f"VirusTotal unavailable (HTTPError {error.code})")
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            logger.warning("event=anti_bot_error url=%s error=%s", url, type(error).__name__)
            decision = self.unknown(f"VirusTotal unavailable ({type(error).__name__})")

        self.set_cached(cache_key, decision)
        return decision

    def check_urls_in_text(self, text):
        import re
        urls = re.findall(r'https?://[^\s]+', text)
        for url in urls:
            decision = self.check_url(url)
            if not decision.allowed:
                return decision
        return None

    @staticmethod
    def unknown(reason):
        return ReputationDecision("UNKNOWN", reason)
