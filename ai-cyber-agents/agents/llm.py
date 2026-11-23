"""Thin wrapper around the Anthropic SDK so tests can swap in a fake."""
import anthropic

_client = None


def client():
    global _client
    if _client is None:
        _client = anthropic.Anthropic(max_retries=4)
    return _client


def create(**kwargs):
    """Non-streaming call. Uses the beta endpoint when `betas` is passed."""
    if "betas" in kwargs:
        return client().beta.messages.create(**kwargs)
    return client().messages.create(**kwargs)


def stream(**kwargs):
    """Streaming call (beta endpoint), returns the final message."""
    with client().beta.messages.stream(**kwargs) as s:
        return s.get_final_message()
