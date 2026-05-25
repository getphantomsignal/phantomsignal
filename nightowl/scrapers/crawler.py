"""
NightOwl Web Crawler — Shadow Spider Network
Scrapy-powered async web reconnaissance engine.

Author:  packetsn1ffer
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import scrapy
from scrapy import signals
from scrapy.crawler import CrawlerRunner
from scrapy.http import Response
from scrapy.linkextractors import LinkExtractor
from scrapy.spiders import CrawlSpider, Rule
from scrapy.utils.log import configure_logging
from scrapy.utils.project import get_project_settings
from twisted.internet import asyncioreactor

logger = logging.getLogger("nightowl.crawler")


class NightOwlSpider(CrawlSpider):
    """
    Shadow Spider — the NightOwl core Scrapy spider.
    Harvests all navigable links, forms, emails, API hints,
    technologies, and metadata from a target web presence.
    """
    name = "nightowl_spider"
    custom_settings = {
        "ROBOTSTXT_OBEY": True,
        "CONCURRENT_REQUESTS": 16,
        "DOWNLOAD_DELAY": 1.0,
        "RANDOMIZE_DOWNLOAD_DELAY": True,
        "COOKIES_ENABLED": True,
        "TELNETCONSOLE_ENABLED": False,
        "DEFAULT_REQUEST_HEADERS": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en",
        },
        "DOWNLOADER_MIDDLEWARES": {
            "scrapy.downloadermiddlewares.useragent.UserAgentMiddleware": None,
            "scrapy_user_agents.middlewares.RandomUserAgentMiddleware": 400,
            "scrapy.downloadermiddlewares.retry.RetryMiddleware": 550,
        },
        "ITEM_PIPELINES": {
            "nightowl.scrapers.pipelines.NightOwlPipeline": 300,
        },
        "AUTOTHROTTLE_ENABLED": True,
        "AUTOTHROTTLE_START_DELAY": 0.5,
        "AUTOTHROTTLE_MAX_DELAY": 10,
        "HTTPCACHE_ENABLED": False,
        "LOG_LEVEL": "WARNING",
    }

    rules = (
        Rule(LinkExtractor(deny_extensions=[
            "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2",
            "ttf", "eot", "mp4", "mp3", "zip", "tar", "gz", "pdf",
        ]), callback="parse_page", follow=True),
    )

    def __init__(self, target: str, depth: int = 2, options: dict = None, *args, **kwargs):
        self.start_urls = [target if target.startswith("http") else f"https://{target}"]
        self.allowed_domains = [urlparse(self.start_urls[0]).netloc]
        self.custom_settings["DEPTH_LIMIT"] = depth
        if options:
            self._apply_options(options)
        super().__init__(*args, **kwargs)
        self.harvested_data: List[Dict] = []

    def _apply_options(self, options: dict) -> None:
        if not options.get("respect_robots", True):
            self.custom_settings["ROBOTSTXT_OBEY"] = False
        if options.get("proxy"):
            self.custom_settings["HTTP_PROXY"] = options["proxy"]
            self.custom_settings["HTTPS_PROXY"] = options["proxy"]
        if options.get("concurrent_requests"):
            self.custom_settings["CONCURRENT_REQUESTS"] = options["concurrent_requests"]

    def parse_page(self, response: Response):
        url = response.url
        parsed = urlparse(url)

        page_data = {
            "type": "web_page",
            "url": url,
            "status_code": response.status,
            "content_type": response.headers.get("Content-Type", b"").decode("utf-8", errors="ignore"),
            "title": response.css("title::text").get(""),
            "description": response.css('meta[name="description"]::attr(content)').get(""),
            "headers": self._parse_headers(response),
            "links": self._extract_links(response),
            "forms": self._extract_forms(response),
            "emails": self._extract_emails(response),
            "phone_numbers": self._extract_phones(response),
            "api_hints": self._extract_api_hints(response),
            "js_files": self._extract_js_files(response),
            "comments": self._extract_html_comments(response),
            "meta_tags": self._extract_meta_tags(response),
            "social_links": self._extract_social_links(response),
            "security_headers": self._analyze_security_headers(response),
        }

        self.harvested_data.append(page_data)
        yield page_data

    def _parse_headers(self, response: Response) -> Dict[str, str]:
        return {
            k.decode("utf-8", errors="ignore"): v.decode("utf-8", errors="ignore")
            for k, v in response.headers.items()
        }

    def _extract_links(self, response: Response) -> List[str]:
        links = set()
        for href in response.css("a::attr(href)").getall():
            full = urljoin(response.url, href)
            links.add(full)
        return list(links)[:200]

    def _extract_forms(self, response: Response) -> List[Dict]:
        forms = []
        for form in response.css("form"):
            forms.append({
                "action": form.attrib.get("action", ""),
                "method": form.attrib.get("method", "get").upper(),
                "inputs": [
                    {
                        "name": inp.attrib.get("name", ""),
                        "type": inp.attrib.get("type", "text"),
                        "id": inp.attrib.get("id", ""),
                    }
                    for inp in form.css("input, textarea, select")
                ],
            })
        return forms

    def _extract_emails(self, response: Response) -> List[str]:
        import re
        emails = set(re.findall(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            response.text
        ))
        return list(emails)

    def _extract_phones(self, response: Response) -> List[str]:
        import re
        phones = set(re.findall(
            r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
            response.text
        ))
        return list(phones)

    def _extract_api_hints(self, response: Response) -> List[Dict]:
        import re
        hints = []
        api_patterns = [
            (r"/api/v?\d*/[\w/]+", "REST API path"),
            (r"/graphql", "GraphQL endpoint"),
            (r"swagger\.json|swagger\.yaml|openapi\.json", "OpenAPI spec"),
            (r"/\.well-known/[\w\-]+", "Well-known resource"),
            (r"api[_\-]?key\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})", "API key in source"),
            (r"authorization\s*[:=]\s*['\"]?Bearer\s+([A-Za-z0-9_\-\.]+)", "Bearer token"),
        ]
        for pattern, label in api_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            for match in matches:
                hints.append({"type": label, "value": match})
        return hints

    def _extract_js_files(self, response: Response) -> List[str]:
        files = response.css("script::attr(src)").getall()
        return [urljoin(response.url, f) for f in files if f]

    def _extract_html_comments(self, response: Response) -> List[str]:
        import re
        comments = re.findall(r"<!--(.*?)-->", response.text, re.DOTALL)
        return [c.strip() for c in comments if len(c.strip()) > 3][:20]

    def _extract_meta_tags(self, response: Response) -> Dict[str, str]:
        meta = {}
        for tag in response.css("meta"):
            name = tag.attrib.get("name") or tag.attrib.get("property", "")
            content = tag.attrib.get("content", "")
            if name and content:
                meta[name] = content
        return meta

    def _extract_social_links(self, response: Response) -> Dict[str, str]:
        social = {}
        platforms = {
            "twitter.com": "twitter", "x.com": "twitter",
            "facebook.com": "facebook", "linkedin.com": "linkedin",
            "instagram.com": "instagram", "youtube.com": "youtube",
            "github.com": "github", "reddit.com": "reddit",
            "tiktok.com": "tiktok", "discord.com": "discord",
            "telegram.me": "telegram", "t.me": "telegram",
        }
        for link in response.css("a::attr(href)").getall():
            for domain, name in platforms.items():
                if domain in link:
                    social[name] = link
        return social

    def _analyze_security_headers(self, response: Response) -> Dict[str, Any]:
        headers = {k.decode().lower(): v.decode() for k, v in response.headers.items()}
        security_headers = {
            "content-security-policy": headers.get("content-security-policy"),
            "x-frame-options": headers.get("x-frame-options"),
            "x-xss-protection": headers.get("x-xss-protection"),
            "x-content-type-options": headers.get("x-content-type-options"),
            "strict-transport-security": headers.get("strict-transport-security"),
            "referrer-policy": headers.get("referrer-policy"),
            "permissions-policy": headers.get("permissions-policy"),
        }
        missing = [k for k, v in security_headers.items() if not v]
        return {
            "present": {k: v for k, v in security_headers.items() if v},
            "missing": missing,
            "score": int((len(security_headers) - len(missing)) / len(security_headers) * 100),
        }


class WebCrawler:
    """NightOwl Web Crawler — manages Scrapy spider lifecycle."""

    def __init__(self, config):
        self.config = config

    async def crawl(self, target: str, depth: int = 2, options: dict = None) -> List[Dict]:
        """Launch a shadow spider against the target."""
        results = []

        try:
            configure_logging(install_root_handler=False)
            settings = get_project_settings()
            settings.setdict({
                "LOG_ENABLED": False,
                "ROBOTSTXT_OBEY": self.config.get("scraper", "respect_robots_txt", default=True),
                "DOWNLOAD_DELAY": self.config.get("scraper", "download_delay", default=1.0),
                "CONCURRENT_REQUESTS": self.config.get("scraper", "concurrent_requests", default=16),
            })

            runner = CrawlerRunner(settings)
            spider_results = []

            def item_scraped(item, response, spider):
                spider_results.append(dict(item))

            crawler = runner.create_crawler(NightOwlSpider)
            crawler.signals.connect(item_scraped, signal=signals.item_scraped)

            deferred = runner.crawl(
                NightOwlSpider,
                target=target,
                depth=depth,
                options=options or {},
            )

            from twisted.internet import defer, reactor
            d = defer.Deferred()

            def on_complete(_):
                d.callback(spider_results)

            deferred.addCallback(on_complete)
            deferred.addErrback(lambda f: d.errback(f))

            results = await asyncio.get_event_loop().run_in_executor(
                None, self._run_twisted_crawl, target, depth, options
            )
        except Exception as e:
            logger.error(f"Crawler error for {target}: {e}")
            results = await self._fallback_crawl(target)

        formatted = []
        for item in results:
            formatted.append({
                "type": "web_page",
                "source": "web_crawler",
                "data": item,
                "confidence": 1.0,
                "relevance_score": 0.8,
                "tags": ["web", "crawl"],
            })
        return formatted

    def _run_twisted_crawl(self, target: str, depth: int, options: dict) -> List[Dict]:
        """Run Scrapy in a blocking thread (Twisted reactor)."""
        import threading
        results = []
        done = threading.Event()

        try:
            from scrapy.crawler import CrawlerProcess
            process = CrawlerProcess({
                "LOG_ENABLED": False,
                "ROBOTSTXT_OBEY": self.config.get("scraper", "respect_robots_txt", default=True),
            })

            spider_inst = None

            def on_spider_opened(spider):
                nonlocal spider_inst
                spider_inst = spider

            def run():
                process.crawl(
                    NightOwlSpider,
                    target=target,
                    depth=depth,
                    options=options or {},
                )
                process.start()
                done.set()

            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            done.wait(timeout=120)

            if spider_inst:
                results = spider_inst.harvested_data

        except Exception as e:
            logger.error(f"Twisted crawl error: {e}")

        return results

    async def _fallback_crawl(self, target: str) -> List[Dict]:
        """Fallback crawler using httpx when Scrapy is unavailable."""
        import re
        import httpx

        results = []
        url = target if target.startswith("http") else f"https://{target}"

        headers = {"User-Agent": "Mozilla/5.0 (compatible; NightOwl/1.0; +https://github.com/nightowl-osint/nightowl)"}

        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=30) as client:
                response = await client.get(url, headers=headers)
                emails = set(re.findall(
                    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
                    response.text
                ))
                results.append({
                    "url": str(response.url),
                    "status_code": response.status_code,
                    "content_type": response.headers.get("content-type", ""),
                    "headers": dict(response.headers),
                    "emails": list(emails),
                    "title": re.search(r"<title[^>]*>(.*?)</title>", response.text, re.IGNORECASE | re.DOTALL),
                })
        except Exception as e:
            logger.error(f"Fallback crawl error: {e}")

        return results
