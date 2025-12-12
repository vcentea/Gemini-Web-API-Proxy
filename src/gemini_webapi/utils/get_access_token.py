import os
import re
import asyncio
from asyncio import Task
from pathlib import Path
from urllib.parse import urlencode

from httpx import AsyncClient, Response, Cookies

from ..constants import Endpoint, Headers
from ..exceptions import AuthError
from .load_browser_cookies import load_browser_cookies
from .logger import logger

# Consent page URL pattern
CONSENT_URL_PATTERN = re.compile(r"consent\.google\.com")


async def handle_consent_redirect(
    proxy: str | None,
    consent_response: Response,
    cookies: dict,
    verbose: bool = False
) -> tuple[Response | None, dict]:
    """
    Handle Google consent redirect for EU/GDPR regions.
    
    Mimics the exact curl command that worked:
    curl -sS -L -b "cookies" -c cookiejar -X POST consent.google.com/save --data-urlencode ...
    
    Key: POST with auth cookies, follow redirects, collect all cookies from the chain.
    """
    consent_html = consent_response.text
    consent_url = str(consent_response.url)
    
    if verbose:
        logger.debug(f"[CONSENT] Consent page URL: {consent_url}")
    
    # Extract form data from consent page HTML
    # Look for "Accept all" form (has set_sc=true, set_aps=true in hidden fields)
    form_data = {}
    
    # Find ALL hidden inputs in the page
    # Pattern: <input type="hidden" name="X" value="Y"> (order may vary)
    for match in re.finditer(r'<input[^>]+>', consent_html, re.IGNORECASE):
        tag = match.group(0)
        if 'type="hidden"' not in tag.lower() and "type='hidden'" not in tag.lower():
            continue
        name_match = re.search(r'name=["\']([^"\']+)["\']', tag)
        value_match = re.search(r'value=["\']([^"\']*)["\']', tag)
        if name_match:
            name = name_match.group(1)
            value = value_match.group(1) if value_match else ""
            # Only keep relevant form fields (avoid duplicates from multiple forms)
            if name not in form_data:
                form_data[name] = value
    
    # Ensure "Accept all" values are set
    form_data["set_eom"] = "false"
    form_data["set_sc"] = "true"
    form_data["set_aps"] = "true"
    
    if verbose:
        logger.debug(f"[CONSENT] Form fields: {list(form_data.keys())}")
    
    if not form_data.get("escs"):
        if verbose:
            logger.warning("[CONSENT] Missing escs token - cannot submit consent")
        return None, cookies
    
    # Build form body exactly like curl --data-urlencode
    form_body = urlencode(form_data)
    
    if verbose:
        logger.debug(f"[CONSENT] POST body length: {len(form_body)}")
    
    # POST to consent.google.com/save - exactly like curl
    # Key: Use ONLY the original auth cookies (PSID, PSIDTS), follow redirects
    try:
        async with AsyncClient(
            proxy=proxy,
            follow_redirects=True,
            verify=False,
            timeout=30.0,
        ) as client:
            # Set cookies exactly like curl -b "name=value; name2=value2"
            for name, value in cookies.items():
                if name.startswith("__Secure-") or name in ["SOCS", "NID", "AEC"]:
                    client.cookies.set(name, value, domain=".google.com")
            
            if verbose:
                logger.debug(f"[CONSENT] Cookies being sent: {list(client.cookies.keys())}")
            
            # POST with headers matching curl
            response = await client.post(
                "https://consent.google.com/save",
                content=form_body,
                headers={
                    **Headers.GEMINI.value,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://consent.google.com",
                    "Referer": consent_url,
                },
            )
            
            final_url = str(response.url)
            if verbose:
                logger.debug(f"[CONSENT] POST chain ended at: {response.status_code} {final_url}")
            
            # Collect ALL cookies from the entire redirect chain
            all_cookies = {}
            for cookie in client.cookies.jar:
                all_cookies[cookie.name] = cookie.value
            
            if verbose:
                logger.debug(f"[CONSENT] Cookies after POST chain: {list(all_cookies.keys())}")
            
            # Check if we got SOCS
            if "SOCS" in all_cookies:
                if verbose:
                    logger.info(f"[CONSENT] Got SOCS: {all_cookies['SOCS'][:20]}...")
                
                # Merge with original cookies
                merged = {**cookies, **all_cookies}
                
                # Check if we ended up at Gemini successfully
                if "gemini.google.com" in final_url and response.status_code == 200:
                    if verbose:
                        logger.info("[CONSENT] SUCCESS - ended at Gemini after consent")
                    return response, merged
                
                # If we're still at consent or got redirected elsewhere, 
                # try one more request to Gemini with all cookies
                if "consent.google.com" in final_url or response.status_code != 200:
                    if verbose:
                        logger.debug("[CONSENT] Making final Gemini request with merged cookies")
                    
                    # Reset cookies and try Gemini
                    client.cookies.clear()
                    for name, value in merged.items():
                        if isinstance(value, str):
                            client.cookies.set(name, value, domain=".google.com")
                    
                    gemini_response = await client.get(
                        Endpoint.INIT.value,
                        headers=Headers.GEMINI.value,
                    )
                    
                    gemini_url = str(gemini_response.url)
                    if verbose:
                        logger.debug(f"[CONSENT] Gemini response: {gemini_response.status_code} {gemini_url}")
                    
                    # Collect any new cookies
                    for cookie in client.cookies.jar:
                        if cookie.name not in merged:
                            merged[cookie.name] = cookie.value
                    
                    if "gemini.google.com" in gemini_url and gemini_response.status_code == 200:
                        return gemini_response, merged
                    
                    if "CookieMismatch" in gemini_url:
                        if verbose:
                            logger.warning("[CONSENT] CookieMismatch - location mismatch detected")
                    
                    return None, merged
                
                return response, merged
            else:
                if verbose:
                    logger.warning(f"[CONSENT] No SOCS cookie received")
                return None, cookies
                
    except Exception as e:
        if verbose:
            logger.error(f"[CONSENT] Error: {e}")
        return None, cookies


async def send_request(
    cookies: dict, proxy: str | None = None, verbose: bool = False
) -> tuple[Response | None, dict]:
    """
    Send http request with provided cookies.
    Handles consent redirect automatically for EU/GDPR regions.
    """

    async with AsyncClient(
        proxy=proxy,
        headers=Headers.GEMINI.value,
        cookies=cookies,
        follow_redirects=True,
        verify=False,
    ) as client:
        response = await client.get(Endpoint.INIT.value)
        
        # Check if we were redirected to consent page
        final_url = str(response.url)
        if CONSENT_URL_PATTERN.search(final_url):
            if verbose:
                logger.info("[CONSENT] Detected consent redirect, handling automatically...")
            
            # Handle consent - use fresh clients for POST to avoid cookie pollution
            consent_result, updated_cookies = await handle_consent_redirect(
                proxy=proxy,
                consent_response=response,
                cookies=cookies,
                verbose=verbose
            )
            
            if consent_result is not None:
                response = consent_result
                cookies = updated_cookies
            else:
                # Consent handling failed but we might have gotten useful cookies
                cookies = updated_cookies
                if verbose:
                    logger.warning("[CONSENT] Consent handling failed, cookies may still be usable")
        
        response.raise_for_status()
        return response, cookies


async def get_access_token(
    base_cookies: dict, proxy: str | None = None, verbose: bool = False
) -> tuple[str, dict]:
    """
    Send a get request to gemini.google.com for each group of available cookies and return
    the value of "SNlM0e" as access token on the first successful request.

    Possible cookie sources:
    - Base cookies passed to the function.
    - __Secure-1PSID from base cookies with __Secure-1PSIDTS from cache.
    - Local browser cookies (if optional dependency `browser-cookie3` is installed).

    Parameters
    ----------
    base_cookies : `dict`
        Base cookies to be used in the request.
    proxy: `str`, optional
        Proxy URL.
    verbose: `bool`, optional
        If `True`, will print more infomation in logs.

    Returns
    -------
    `str`
        Access token.
    `dict`
        Cookies of the successful request.

    Raises
    ------
    `gemini_webapi.AuthError`
        If all requests failed.
    """

    async with AsyncClient(proxy=proxy, follow_redirects=True, verify=False) as client:
        response = await client.get(Endpoint.GOOGLE.value)

    extra_cookies = {}
    if response.status_code == 200:
        extra_cookies = response.cookies

    tasks = []

    # Base cookies passed directly on initializing client
    if "__Secure-1PSID" in base_cookies and "__Secure-1PSIDTS" in base_cookies:
        tasks.append(Task(send_request({**extra_cookies, **base_cookies}, proxy=proxy, verbose=verbose)))
    elif verbose:
        logger.debug(
            "Skipping loading base cookies. Either __Secure-1PSID or __Secure-1PSIDTS is not provided."
        )

    # Cached cookies in local file
    cache_dir = (
        (GEMINI_COOKIE_PATH := os.getenv("GEMINI_COOKIE_PATH"))
        and Path(GEMINI_COOKIE_PATH)
        or (Path(__file__).parent / "temp")
    )
    if "__Secure-1PSID" in base_cookies:
        filename = f".cached_1psidts_{base_cookies['__Secure-1PSID']}.txt"
        cache_file = cache_dir / filename
        if cache_file.is_file():
            cached_1psidts = cache_file.read_text()
            if cached_1psidts:
                cached_cookies = {
                    **extra_cookies,
                    **base_cookies,
                    "__Secure-1PSIDTS": cached_1psidts,
                }
                tasks.append(Task(send_request(cached_cookies, proxy=proxy, verbose=verbose)))
            elif verbose:
                logger.debug("Skipping loading cached cookies. Cache file is empty.")
        elif verbose:
            logger.debug("Skipping loading cached cookies. Cache file not found.")
    else:
        valid_caches = 0
        cache_files = cache_dir.glob(".cached_1psidts_*.txt")
        for cache_file in cache_files:
            cached_1psidts = cache_file.read_text()
            if cached_1psidts:
                cached_cookies = {
                    **extra_cookies,
                    "__Secure-1PSID": cache_file.stem[16:],
                    "__Secure-1PSIDTS": cached_1psidts,
                }
                tasks.append(Task(send_request(cached_cookies, proxy=proxy, verbose=verbose)))
                valid_caches += 1

        if valid_caches == 0 and verbose:
            logger.debug(
                "Skipping loading cached cookies. Cookies will be cached after successful initialization."
            )

    # Browser cookies (if browser-cookie3 is installed)
    try:
        valid_browser_cookies = 0
        browser_cookies = load_browser_cookies(
            domain_name="google.com", verbose=verbose
        )
        if browser_cookies:
            for browser, cookies in browser_cookies.items():
                if secure_1psid := cookies.get("__Secure-1PSID"):
                    if (
                        "__Secure-1PSID" in base_cookies
                        and base_cookies["__Secure-1PSID"] != secure_1psid
                    ):
                        if verbose:
                            logger.debug(
                                f"Skipping loading local browser cookies from {browser}. "
                                f"__Secure-1PSID does not match the one provided."
                            )
                        continue

                    local_cookies = {"__Secure-1PSID": secure_1psid}
                    if secure_1psidts := cookies.get("__Secure-1PSIDTS"):
                        local_cookies["__Secure-1PSIDTS"] = secure_1psidts
                    if nid := cookies.get("NID"):
                        local_cookies["NID"] = nid
                    tasks.append(Task(send_request(local_cookies, proxy=proxy, verbose=verbose)))
                    valid_browser_cookies += 1
                    if verbose:
                        logger.debug(f"Loaded local browser cookies from {browser}")

        if valid_browser_cookies == 0 and verbose:
            logger.debug(
                "Skipping loading local browser cookies. Login to gemini.google.com in your browser first."
            )
    except ImportError:
        if verbose:
            logger.debug(
                "Skipping loading local browser cookies. Optional dependency 'browser-cookie3' is not installed."
            )
    except Exception as e:
        if verbose:
            logger.warning(f"Skipping loading local browser cookies. {e}")

    if not tasks:
        raise AuthError(
            "No valid cookies available for initialization. Please pass __Secure-1PSID and __Secure-1PSIDTS manually."
        )

    for i, future in enumerate(asyncio.as_completed(tasks)):
        try:
            response, request_cookies = await future
            match = re.search(r'"SNlM0e":"(.*?)"', response.text)
            if match:
                if verbose:
                    logger.debug(
                        f"Init attempt ({i + 1}/{len(tasks)}) succeeded. Initializing client..."
                    )
                return match.group(1), request_cookies
            elif verbose:
                logger.debug(
                    f"Init attempt ({i + 1}/{len(tasks)}) failed. Cookies invalid."
                )
        except Exception as e:
            if verbose:
                logger.debug(
                    f"Init attempt ({i + 1}/{len(tasks)}) failed with error: {e}"
                )

    raise AuthError(
        "Failed to initialize client. SECURE_1PSIDTS could get expired frequently, please make sure cookie values are up to date. "
        f"(Failed initialization attempts: {len(tasks)})"
    )
