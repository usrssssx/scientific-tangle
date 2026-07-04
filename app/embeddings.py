from __future__ import annotations

import hashlib
import math
import re
import struct
from typing import Iterable


EMBEDDING_MODEL = "hashed-bow-v1"
EMBEDDING_DIMS = 96
TOKEN_RE = re.compile(r"[a-zA-Zа-яА-ЯёЁ0-9_]{2,}")


def embedding_text_tokens(text: str) -> list[str]:
    normalized = text.lower().replace("ё", "е")
    return TOKEN_RE.findall(normalized)


def _hash_bucket(token: str, dims: int) -> tuple[int, float]:
    digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
    value = int.from_bytes(digest, "big")
    return value % dims, -1.0 if value & 1 else 1.0


def embed_text(text: str, dims: int = EMBEDDING_DIMS) -> tuple[float, ...]:
    vector = [0.0] * dims
    for token in embedding_text_tokens(text):
        bucket, sign = _hash_bucket(token, dims)
        # Sublinear term frequency keeps boilerplate-heavy chunks from dominating.
        vector[bucket] += sign
        if len(token) > 5:
            for index in range(0, len(token) - 2):
                ngram = token[index:index + 3]
                bucket, sign = _hash_bucket(f"ng:{ngram}", dims)
                vector[bucket] += sign * 0.2
    norm = math.sqrt(sum(value * value for value in vector))
    if not norm:
        return tuple(vector)
    return tuple(value / norm for value in vector)


def vector_to_blob(vector: Iterable[float]) -> bytes:
    values = tuple(float(value) for value in vector)
    return struct.pack(f">{len(values)}f", *values)


def blob_to_vector(blob: bytes, dims: int = EMBEDDING_DIMS) -> tuple[float, ...]:
    if not blob:
        return tuple(0.0 for _ in range(dims))
    length = len(blob) // 4
    return struct.unpack(f">{length}f", blob)


def cosine_similarity(left: Iterable[float], right: Iterable[float]) -> float:
    return float(sum(a * b for a, b in zip(left, right)))
