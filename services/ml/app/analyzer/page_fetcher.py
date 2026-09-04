"""
PhishNetra - Isolated Page Acquisition & Browser Automation Engine
Module: services.ml.app.analyzer.page_fetcher
Milestone: 3
"""

import time
import base64
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple

import httpx
from app.security.ssrf import ssrf_validator


class IsolatedPageFetcher:
    """
    Secure isolated browser automation and sandbox fetching pipeline.
    Enforces SSRF defense, DNS rebinding checks, redirect limits, and passive inspection.
    """

    MAX_REDIRECTS = 5
    NAVIGATION_TIMEOUT_MS = 10000
    TOTAL_TIMEOUT_SECONDS = 15.0
    MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB

    @classmethod
    async def fetch_page(
        cls,
        target_url: str,
        capture_screenshot: bool = False,
        timeout_ms: int = 10000
    ) -> Dict[str, Any]:
        """
        Executes safe page acquisition with strict security shields.
        """
        start_time = time.time()

        # Step 1: Pre-flight URL & Hostname Validation
        is_safe, block_reason, hostname = ssrf_validator.validate_url(target_url)
        if not is_safe:
            return {
                "status": "BLOCKED",
                "requestedUrl": target_url,
                "finalUrl": target_url,
                "blockReason": block_reason,
                "redirectCount": 0,
                "redirectChain": [],
                "html": "",
                "screenshot": None,
                "networkMetrics": {
                    "totalRequests": 0,
                    "uniqueDomains": [],
                    "thirdPartyDomains": [],
                    "scriptsLoaded": 0,
                    "iframesLoaded": 0,
                    "externalFormActions": 0,
                    "blockedRequestsCount": 1
                },
                "acquisitionTimeMs": round((time.time() - start_time) * 1000, 2)
            }

        # Step 2: Pre-flight DNS Resolution & Rebinding Check
        port = 443 if target_url.lower().startswith("https:") else 80
        is_dns_safe, dns_reason, resolved_ips = ssrf_validator.resolve_and_validate(hostname, port)
        if not is_dns_safe:
            return {
                "status": "BLOCKED",
                "requestedUrl": target_url,
                "finalUrl": target_url,
                "blockReason": dns_reason,
                "redirectCount": 0,
                "redirectChain": [],
                "html": "",
                "screenshot": None,
                "networkMetrics": {
                    "totalRequests": 0,
                    "uniqueDomains": [hostname] if hostname else [],
                    "thirdPartyDomains": [],
                    "scriptsLoaded": 0,
                    "iframesLoaded": 0,
                    "externalFormActions": 0,
                    "blockedRequestsCount": 1
                },
                "acquisitionTimeMs": round((time.time() - start_time) * 1000, 2)
            }

        # Step 3: Attempt Playwright Headless Browser Acquisition
        playwright_result = await cls._fetch_with_playwright(
            target_url,
            capture_screenshot=capture_screenshot,
            timeout_ms=timeout_ms
        )

        if playwright_result is not None:
            playwright_result["acquisitionTimeMs"] = round((time.time() - start_time) * 1000, 2)
            return playwright_result

        # Step 4: Fallback to Secure HTTPX Sandbox Fetcher
        fallback_result = await cls._fetch_with_httpx_sandbox(
            target_url,
            timeout_seconds=min(10.0, timeout_ms / 1000.0)
        )
        fallback_result["acquisitionTimeMs"] = round((time.time() - start_time) * 1000, 2)
        return fallback_result

    @classmethod
    async def _fetch_with_playwright(
        cls,
        target_url: str,
        capture_screenshot: bool = False,
        timeout_ms: int = 10000
    ) -> Optional[Dict[str, Any]]:
        """
        Executes isolated browser context with Playwright Chromium.
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return None

        redirect_chain: List[Dict[str, Any]] = []
        network_requests: List[Dict[str, Any]] = []
        blocked_requests_count = 0
        final_url = target_url

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--disable-gpu",
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-extensions",
                        "--disable-remote-fonts",
                        "--disable-background-networking"
                    ]
                )

                # Fresh isolated context for this analysis only
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    java_script_enabled=True,
                    ignore_https_errors=True,
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 PhishNetra/1.0"
                )

                page = await context.new_page()

                # Intercept network requests to enforce SSRF per sub-request
                async def route_handler(route):
                    nonlocal blocked_requests_count
                    req = route.request
                    req_url = req.url

                    # Block file:// and non-http schemes
                    if not req_url.startswith(("http://", "https://")):
                        blocked_requests_count += 1
                        await route.abort("blockedbyclient")
                        return

                    safe, _, req_host = ssrf_validator.validate_url(req_url)
                    if not safe or not req_host:
                        blocked_requests_count += 1
                        await route.abort("blockedbyclient")
                        return

                    network_requests.append({
                        "url": req_url,
                        "method": req.method,
                        "resourceType": req.resource_type,
                        "host": req_host
                    })
                    await route.continue_()

                await page.route("**/*", route_handler)

                # Redirect & Response Monitoring
                def handle_response(response):
                    if response.status in (301, 302, 303, 307, 308):
                        redirect_chain.append({
                            "url": response.url,
                            "status": response.status,
                            "headers": dict(response.headers)
                        })

                page.on("response", handle_response)

                try:
                    response = await page.goto(
                        target_url,
                        wait_until="domcontentloaded",
                        timeout=timeout_ms
                    )
                    final_url = page.url
                except Exception as nav_err:
                    err_msg = str(nav_err)
                    if "Timeout" in err_msg:
                        await context.close()
                        await browser.close()
                        return {
                            "status": "TIMEOUT",
                            "requestedUrl": target_url,
                            "finalUrl": target_url,
                            "error": f"Navigation timeout exceeded ({timeout_ms}ms)",
                            "redirectCount": len(redirect_chain),
                            "redirectChain": redirect_chain,
                            "html": "",
                            "screenshot": None,
                            "networkMetrics": cls._compute_network_metrics(target_url, network_requests, blocked_requests_count)
                        }
                    # Fallback to HTTPX if browser navigation fails
                    await context.close()
                    await browser.close()
                    return None

                # Check intermediate redirect chain limit
                if len(redirect_chain) > cls.MAX_REDIRECTS:
                    await context.close()
                    await browser.close()
                    return {
                        "status": "BLOCKED",
                        "requestedUrl": target_url,
                        "finalUrl": final_url,
                        "blockReason": f"Exceeded maximum redirect limit ({len(redirect_chain)} > {cls.MAX_REDIRECTS})",
                        "redirectCount": len(redirect_chain),
                        "redirectChain": redirect_chain,
                        "html": "",
                        "screenshot": None,
                        "networkMetrics": cls._compute_network_metrics(target_url, network_requests, blocked_requests_count)
                    }

                # Validate final URL destination for SSRF
                final_safe, final_reason, final_host = ssrf_validator.validate_url(final_url)
                if not final_safe:
                    await context.close()
                    await browser.close()
                    return {
                        "status": "BLOCKED",
                        "requestedUrl": target_url,
                        "finalUrl": final_url,
                        "blockReason": f"Final redirect target blocked: {final_reason}",
                        "redirectCount": len(redirect_chain),
                        "redirectChain": redirect_chain,
                        "html": "",
                        "screenshot": None,
                        "networkMetrics": cls._compute_network_metrics(target_url, network_requests, blocked_requests_count)
                    }

                html_content = await page.content()
                page_title = await page.title()

                # Optional Screenshot Thumbnail
                screenshot_dict = None
                if capture_screenshot:
                    try:
                        screenshot_bytes = await page.screenshot(type="jpeg", quality=60)
                        screenshot_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")
                        screenshot_dict = {
                            "available": True,
                            "width": 1280,
                            "height": 800,
                            "mimeType": "image/jpeg",
                            "base64Preview": f"data:image/jpeg;base64,{screenshot_b64}"
                        }
                    except Exception:
                        pass

                # Explicitly close isolated context and browser
                await context.close()
                await browser.close()

                return {
                    "status": "COMPLETED",
                    "requestedUrl": target_url,
                    "finalUrl": final_url,
                    "pageTitle": page_title,
                    "redirectCount": len(redirect_chain),
                    "redirectChain": redirect_chain,
                    "html": html_content,
                    "screenshot": screenshot_dict,
                    "networkMetrics": cls._compute_network_metrics(target_url, network_requests, blocked_requests_count)
                }

        except Exception:
            # Fallback to HTTPX
            return None

    @classmethod
    async def _fetch_with_httpx_sandbox(
        cls,
        target_url: str,
        timeout_seconds: float = 10.0
    ) -> Dict[str, Any]:
        """
        Secure sandbox fetcher using HTTPX with manual redirect chain validation.
        """
        current_url = target_url
        redirect_chain: List[Dict[str, Any]] = []
        redirect_count = 0

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=timeout_seconds,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 PhishNetra/1.0"
            }
        ) as client:
            while redirect_count <= cls.MAX_REDIRECTS:
                # Validate current hop
                safe, reason, host = ssrf_validator.validate_url(current_url)
                if not safe:
                    return {
                        "status": "BLOCKED",
                        "requestedUrl": target_url,
                        "finalUrl": current_url,
                        "blockReason": f"Hop blocked by SSRF shield: {reason}",
                        "redirectCount": redirect_count,
                        "redirectChain": redirect_chain,
                        "html": "",
                        "screenshot": None,
                        "networkMetrics": {
                            "totalRequests": redirect_count + 1,
                            "uniqueDomains": [host] if host else [],
                            "thirdPartyDomains": [],
                            "scriptsLoaded": 0,
                            "iframesLoaded": 0,
                            "externalFormActions": 0,
                            "blockedRequestsCount": 1
                        }
                    }

                try:
                    resp = await client.get(current_url)
                except httpx.TimeoutException:
                    return {
                        "status": "TIMEOUT",
                        "requestedUrl": target_url,
                        "finalUrl": current_url,
                        "error": f"Request timed out after {timeout_seconds}s",
                        "redirectCount": redirect_count,
                        "redirectChain": redirect_chain,
                        "html": "",
                        "screenshot": None,
                        "networkMetrics": {
                            "totalRequests": redirect_count + 1,
                            "uniqueDomains": [host] if host else [],
                            "thirdPartyDomains": [],
                            "scriptsLoaded": 0,
                            "iframesLoaded": 0,
                            "externalFormActions": 0,
                            "blockedRequestsCount": 0
                        }
                    }
                except Exception as ex:
                    return {
                        "status": "FAILED",
                        "requestedUrl": target_url,
                        "finalUrl": current_url,
                        "error": f"Sandbox fetch error: {str(ex)}",
                        "redirectCount": redirect_count,
                        "redirectChain": redirect_chain,
                        "html": "",
                        "screenshot": None,
                        "networkMetrics": {
                            "totalRequests": redirect_count + 1,
                            "uniqueDomains": [host] if host else [],
                            "thirdPartyDomains": [],
                            "scriptsLoaded": 0,
                            "iframesLoaded": 0,
                            "externalFormActions": 0,
                            "blockedRequestsCount": 0
                        }
                    }

                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location")
                    if not loc:
                        break
                    next_url = urllib.parse.urljoin(current_url, loc)
                    redirect_chain.append({
                        "url": current_url,
                        "status": resp.status_code,
                        "headers": dict(resp.headers)
                    })
                    current_url = next_url
                    redirect_count += 1
                else:
                    # Final content acquired
                    return {
                        "status": "COMPLETED",
                        "requestedUrl": target_url,
                        "finalUrl": current_url,
                        "redirectCount": redirect_count,
                        "redirectChain": redirect_chain,
                        "html": resp.text[:cls.MAX_RESPONSE_BYTES],
                        "screenshot": None,
                        "networkMetrics": {
                            "totalRequests": redirect_count + 1,
                            "uniqueDomains": [host] if host else [],
                            "thirdPartyDomains": [],
                            "scriptsLoaded": 0,
                            "iframesLoaded": 0,
                            "externalFormActions": 0,
                            "blockedRequestsCount": 0
                        }
                    }

            return {
                "status": "BLOCKED",
                "requestedUrl": target_url,
                "finalUrl": current_url,
                "blockReason": f"Exceeded maximum redirect limit ({redirect_count} > {cls.MAX_REDIRECTS})",
                "redirectCount": redirect_count,
                "redirectChain": redirect_chain,
                "html": "",
                "screenshot": None,
                "networkMetrics": {
                    "totalRequests": redirect_count,
                    "uniqueDomains": [],
                    "thirdPartyDomains": [],
                    "scriptsLoaded": 0,
                    "iframesLoaded": 0,
                    "externalFormActions": 0,
                    "blockedRequestsCount": 0
                }
            }

    @classmethod
    def _compute_network_metrics(
        cls,
        base_url: str,
        network_requests: List[Dict[str, Any]],
        blocked_count: int
    ) -> Dict[str, Any]:
        base_host = ""
        try:
            base_host = urllib.parse.urlsplit(base_url).netloc.lower().split(":")[0]
        except Exception:
            pass

        unique_hosts = list(set(r.get("host", "") for r in network_requests if r.get("host")))
        third_party = [h for h in unique_hosts if h and h != base_host and not h.endswith("." + base_host)]
        scripts_count = sum(1 for r in network_requests if r.get("resourceType") == "script")
        iframes_count = sum(1 for r in network_requests if r.get("resourceType") in ("document", "iframe"))

        return {
            "totalRequests": len(network_requests),
            "uniqueDomains": unique_hosts,
            "thirdPartyDomains": third_party,
            "scriptsLoaded": scripts_count,
            "iframesLoaded": iframes_count,
            "externalFormActions": 0,
            "blockedRequestsCount": blocked_count
        }


page_fetcher = IsolatedPageFetcher()
