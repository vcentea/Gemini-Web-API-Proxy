import asyncio
import functools
from collections.abc import Callable

from ..exceptions import APIError, ImageGenerationError


def running(retry: int = 0) -> Callable:
    """
    Decorator to check if GeminiClient is running before making a request.

    Parameters
    ----------
    retry: `int`, optional
        Max number of retries when `gemini_webapi.APIError` is raised.
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(client, *args, retry=retry, **kwargs):
            try:
                if not client._running:
                    await client.init(
                        timeout=client.timeout,
                        auto_close=client.auto_close,
                        close_delay=client.close_delay,
                        auto_refresh=client.auto_refresh,
                        refresh_interval=client.refresh_interval,
                        verbose=False,
                    )
                    if client._running:
                        return await func(client, *args, **kwargs)

                    # Should not reach here
                    raise APIError(
                        f"Invalid function call: GeminiClient.{func.__name__}. Client initialization failed."
                    )
                else:
                    return await func(client, *args, **kwargs)
            except APIError as e:
                # CUSTOM FIX: Handle "Loading..." status messages from image generation
                # These are not errors - they mean the image is still being generated
                is_loading_status = (
                    "Invalid response data received" in str(e) and 
                    hasattr(client, '_last_response_text') and 
                    "Loading" in client._last_response_text
                )
                
                # Image generation takes longer and needs more retries
                if isinstance(e, ImageGenerationError):
                    # Allow up to 3 retries for image generation (was limited to 1)
                    retry = min(3, retry)
                    wait_time = 15  # Wait 15 seconds between retries for images
                elif is_loading_status:
                    # "Loading..." status - image is being generated, wait longer
                    retry = min(5, retry)  # Allow up to 5 retries for loading status
                    wait_time = 20  # Wait 20 seconds for image generation to complete
                else:
                    wait_time = 1  # Default wait time for other errors

                if retry > 0:
                    await asyncio.sleep(wait_time)
                    return await wrapper(client, *args, retry=retry - 1, **kwargs)

                raise

        return wrapper

    return decorator
