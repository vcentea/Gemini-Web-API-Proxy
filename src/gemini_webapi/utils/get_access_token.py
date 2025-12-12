import os
import re
import asyncio
from asyncio import Task
from pathlib import Path

from httpx import AsyncClient, Response

from ..constants import Endpoint, Headers
from ..exceptions import AuthError
from .load_browser_cookies import load_browser_cookies
from .logger import logger

# Consent page URL pattern
CONSENT_URL_PATTERN = re.compile(r"consent\.google\.com")


async def handle_consent_redirect(
    client: AsyncClient,
    consent_response: Response,
    cookies: dict,
    verbose: bool = False
) -> tuple[Response | None, dict]:
    """
    Handle Google consent redirect for EU/GDPR regions.
    
    When accessing Gemini from certain regions (EU), Google redirects to a consent page.
    This function programmatically accepts consent and returns the SOCS cookie.
    
    Parameters
    ----------
    client : AsyncClient
        The httpx client that already has the consent page loaded.
    consent_response : Response
        The response containing the consent page HTML.
    cookies : dict
        Current cookies dict to update with SOCS.
    verbose : bool
        Whether to log debug information.
        
    Returns
    -------
    tuple[Response | None, dict]
        The response after consent and updated cookies with SOCS.
    """
    consent_html = consent_response.text
    consent_url = str(consent_response.url)
    
    # Extract form data from consent page
    form_data = {}
    
    # Extract hidden input values using regex
    # Pattern handles both name="x" value="y" and value="y" name="x" orders
    hidden_inputs = re.findall(
        r'<input[^>]*type="hidden"[^>]*name="([^"]*)"[^>]*value="([^"]*)"',
        consent_html
    )
    # Also try reverse order
    hidden_inputs += re.findall(
        r'<input[^>]*name="([^"]*)"[^>]*type="hidden"[^>]*value="([^"]*)"',
        consent_html
    )
    hidden_inputs += re.findall(
        r'<input[^>]*value="([^"]*)"[^>]*name="([^"]*)"[^>]*type="hidden"',
        consent_html
    )
    
    for match in hidden_inputs:
        name, value = match[0], match[1] if len(match) > 1 else ""
        if name in ["bl", "x", "gl", "m", "app", "pc", "continue", "hl", "cm", "escs", "src"]:
            if name not in form_data:  # Don't overwrite
                form_data[name] = value
    
    # Set the "Accept all" specific values
    form_data["set_eom"] = "false"  # Not essential-only mode
    form_data["set_sc"] = "true"    # Set consent cookie
    form_data["set_aps"] = "true"   # Accept personalized services
    
    if verbose:
        logger.debug(f"[CONSENT] Extracted form data: {list(form_data.keys())}")
    
    if not form_data.get("escs"):
        if verbose:
            logger.warning("[CONSENT] Could not extract consent form data (escs missing)")
        return None, cookies
    
    # POST consent acceptance using the same client (preserves cookies/session)
    try:
        post_response = await client.post(
            "https://consent.google.com/save",
            data=form_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://consent.google.com",
                "Referer": consent_url,
            },
            follow_redirects=True,
        )
        
        if verbose:
            logger.debug(f"[CONSENT] POST /save status: {post_response.status_code}")
        
    except Exception as e:
        if verbose:
            logger.warning(f"[CONSENT] POST request failed: {e}")
        return None, cookies
    
    # Check for SOCS cookie in the client's cookie jar
    socs_cookie = None
    for cookie in client.cookies.jar:
        if cookie.name == "SOCS":
            socs_cookie = cookie.value
            if verbose:
                logger.debug(f"[CONSENT] Found SOCS in cookie jar: {socs_cookie[:20]}...")
            break
    
    # Also check response cookies directly
    if not socs_cookie:
        socs_cookie = post_response.cookies.get("SOCS")
        if socs_cookie and verbose:
            logger.debug(f"[CONSENT] Found SOCS in response cookies: {socs_cookie[:20]}...")
    
    if socs_cookie:
        cookies["SOCS"] = socs_cookie
        if verbose:
            logger.info(f"[CONSENT] Successfully obtained SOCS cookie for this region")
        
        # Retry Gemini with SOCS cookie now in the client's jar
        final_response = await client.get(Endpoint.INIT.value, follow_redirects=True)
        
        if verbose:
            logger.debug(f"[CONSENT] Final Gemini request status: {final_response.status_code}, URL: {final_response.url}")
        
        return final_response, cookies
    else:
        if verbose:
            logger.warning(f"[CONSENT] SOCS cookie not found after consent POST (status: {post_response.status_code})")
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
            
            # Handle consent using the same client and already-loaded consent page
            consent_result, updated_cookies = await handle_consent_redirect(
                client=client,
                consent_response=response,
                cookies=cookies,
                verbose=verbose
            )
            
            if consent_result is not None:
                response = consent_result
                cookies = updated_cookies
            else:
                if verbose:
                    logger.warning("[CONSENT] Consent handling failed, continuing with original response")
        
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
