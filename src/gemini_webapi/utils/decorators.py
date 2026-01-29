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
                # CUSTOM FIX: Handle intermediate status responses from Gemini
                # When Gemini is "thinking" or "generating", it returns status-only responses
                # like [["wrb.fr",null,null,null,null,[2]]] or [["wrb.fr",null,null,null,null,[4]]]
                # Status codes:
                #   [2] = "Thinking in progress" (extended thinking/reasoning models)
                #   [4] = "Generating in progress" (model is writing response)
                last_response = getattr(client, '_last_response_text', '')

                is_thinking_status = (
                    "Invalid response data received" in str(e) and
                    last_response and
                    ('null,null,null,[2]' in last_response or 'null,null,null,[4]' in last_response)
                )

                is_loading_status = (
                    "Invalid response data received" in str(e) and
                    last_response and
                    "Loading" in last_response
                )

                # Image generation takes longer and needs more retries
                if isinstance(e, ImageGenerationError):
                    # Allow up to 3 retries for image generation (was limited to 1)
                    retry = min(3, retry)
                    wait_time = 15  # Wait 15 seconds between retries for images
                elif is_thinking_status:
                    # Thinking/Generating in progress - model is processing
                    # This is common for models like gemini-3.0-pro that do extended thinking
                    retry = min(10, max(retry, 10))  # Allow up to 10 retries
                    wait_time = 5  # Wait 5 seconds between retries (total ~50s wait capacity)
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
