"""Page-level inspection and decoding."""


def inspect_page(data: bytes, page_num: int, page_size: int):
    """Inspect a single database page."""
    raise NotImplementedError


def hex_dump(data: bytes, offset: int = 0) -> str:
    """Return formatted hex dump of bytes."""
    raise NotImplementedError


def decode_page_type(raw: int) -> str:
    """Decode btree page type from flag byte."""
    return {2: "index interior", 5: "table interior", 10: "index leaf", 13: "table leaf"}.get(raw, "unknown")
