"""
PNGHider — стеганография в PNG через LSB.

Особенности:
- скрытие данных в RGB/RGBA PNG
- пароль для генерации карты позиций
- опциональное шифрование вторым паролем
- HMAC-проверка целостности
- zlib-сжатие
- защита от повреждённых данных

Формат payload:

    MAGIC      4B
    FLAGS      1B
    SALT       16B
    NONCE      16B
    SIZE       8B
    HMAC       32B
    DATA       N bytes

FLAGS:
    bit0 -> данные зашифрованы
"""

from __future__ import annotations

import hashlib
import hmac
import os
import random
import zlib

import numpy as np
from PIL import Image


# ============================================================================
# Константы
# ============================================================================

_MAGIC = b"PNGH"

_SAMPLE_SIZE = 4096
_STEP = 3

_SALT_SIZE = 16
_NONCE_SIZE = 16
_HMAC_SIZE = 32

_HEADER_SIZE = (
    4
    + 1
    + _SALT_SIZE
    + _NONCE_SIZE
    + 8
    + _HMAC_SIZE
)

_FLAG_ENCRYPTED = 1


# ============================================================================
# Криптография
# ============================================================================

def _derive_key(password: str, salt: bytes) -> bytes:
    """
    Генерирует ключ из пароля через PBKDF2.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        200_000,
        32,
    )


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """
    Генерирует псевдослучайный поток байт.
    """
    out = bytearray()
    counter = 0

    while len(out) < length:
        block = hashlib.sha512(
            key
            + nonce
            + counter.to_bytes(8, "big")
        ).digest()

        out.extend(block)
        counter += 1

    return bytes(out[:length])


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR двух байтовых строк.
    """
    return bytes(x ^ y for x, y in zip(a, b))


def _encrypt(data: bytes, password: str, salt: bytes, nonce: bytes) -> bytes:
    """
    Шифрует данные поточным XOR-шифром.
    """
    key = _derive_key(password, salt)
    stream = _keystream(key, nonce, len(data))
    return _xor_bytes(data, stream)


def _decrypt(data: bytes, password: str, salt: bytes, nonce: bytes) -> bytes:
    """
    Расшифровывает данные.
    """
    return _encrypt(data, password, salt, nonce)


# ============================================================================
# Работа с позициями
# ============================================================================

def _generate_map(
    password: str,
    sample: bytes,
    total_bytes: int,
) -> list[int]:
    """
    Генерирует перемешанную карту позиций.

    Первые SAMPLE_SIZE байт не используются,
    чтобы seed не менялся после записи.
    """
    slots = total_bytes // _STEP

    if slots == 0:
        raise ValueError("Изображение слишком маленькое.")

    seed = int.from_bytes(
        hashlib.sha512(
            password.encode() + sample
        ).digest()[:8],
        "big",
    )

    rng = random.Random(seed)

    positions = [
        i * _STEP
        for i in range(slots)
        if i * _STEP >= _SAMPLE_SIZE
    ]

    rng.shuffle(positions)

    return positions


def _capacity(position_count: int, depth: int) -> int:
    """
    Возвращает вместимость в байтах.
    """
    return position_count * depth // 8


def _slots_needed(byte_count: int, depth: int) -> int:
    """
    Возвращает число LSB-позиций,
    необходимых для хранения byte_count байт.
    """
    bits = byte_count * 8
    return (bits + depth - 1) // depth


# ============================================================================
# Работа с битами
# ============================================================================

def _write_bits(
    pixels: np.ndarray,
    positions: list[int],
    data: bytes,
    depth: int,
) -> None:
    """
    Записывает байты в младшие биты пикселей.
    """
    mask = (1 << depth) - 1
    clear_mask = 0xFF ^ mask

    bit_buffer = 0
    bit_count = 0

    pos_index = 0

    for byte in data:
        bit_buffer = (bit_buffer << 8) | byte
        bit_count += 8

        while bit_count >= depth:
            bit_count -= depth

            value = (
                bit_buffer >> bit_count
            ) & mask

            pos = positions[pos_index]

            pixels[pos] = (
                pixels[pos] & clear_mask
            ) | value

            pos_index += 1

    if bit_count:
        value = (
            bit_buffer << (depth - bit_count)
        ) & mask

        pos = positions[pos_index]

        pixels[pos] = (
            pixels[pos] & clear_mask
        ) | value


def _read_bits(
    pixels: np.ndarray,
    positions: list[int],
    byte_count: int,
    depth: int,
) -> bytes:
    """
    Читает байты из младших бит пикселей.
    """
    mask = (1 << depth) - 1

    out = bytearray()

    bit_buffer = 0
    bit_count = 0

    needed_slots = _slots_needed(byte_count, depth)

    for pos in positions[:needed_slots]:
        value = pixels[pos] & mask

        bit_buffer = (
            bit_buffer << depth
        ) | value

        bit_count += depth

        while bit_count >= 8:
            bit_count -= 8

            out.append(
                (bit_buffer >> bit_count) & 0xFF
            )

            if len(out) == byte_count:
                return bytes(out)

    return bytes(out)


# ============================================================================
# Работа с payload
# ============================================================================

def _build_payload(
    data: bytes,
    encryption_password: str | None,
) -> bytes:
    """
    Создаёт payload для записи.
    """
    flags = 0

    salt = os.urandom(_SALT_SIZE)
    nonce = os.urandom(_NONCE_SIZE)

    compressed = zlib.compress(data)

    if encryption_password:
        flags |= _FLAG_ENCRYPTED

        compressed = _encrypt(
            compressed,
            encryption_password,
            salt,
            nonce,
        )

        hmac_key = _derive_key(
            encryption_password,
            salt,
        )
    else:
        hmac_key = hashlib.sha256(
            salt
        ).digest()

    digest = hmac.new(
        hmac_key,
        compressed,
        hashlib.sha256,
    ).digest()

    return (
        _MAGIC
        + bytes([flags])
        + salt
        + nonce
        + len(compressed).to_bytes(8, "big")
        + digest
        + compressed
    )


def _parse_payload(
    payload: bytes,
    encryption_password: str | None,
) -> bytes:
    """
    Извлекает и проверяет payload.
    """
    if len(payload) < _HEADER_SIZE:
        raise ValueError("Payload слишком короткий.")

    offset = 0

    magic = payload[offset:offset + 4]
    offset += 4

    if magic != _MAGIC:
        raise ValueError(
            "Данные не найдены или пароль неверный."
        )

    flags = payload[offset]
    offset += 1

    salt = payload[offset:offset + _SALT_SIZE]
    offset += _SALT_SIZE

    nonce = payload[offset:offset + _NONCE_SIZE]
    offset += _NONCE_SIZE

    size = int.from_bytes(
        payload[offset:offset + 8],
        "big",
    )

    offset += 8

    expected_hmac = payload[
        offset:offset + _HMAC_SIZE
    ]

    offset += _HMAC_SIZE

    encrypted = payload[
        offset:offset + size
    ]

    if len(encrypted) != size:
        raise ValueError("Payload повреждён.")

    if flags & _FLAG_ENCRYPTED:
        if not encryption_password:
            raise ValueError(
                "Нужен encryption_password."
            )

        hmac_key = _derive_key(
            encryption_password,
            salt,
        )
    else:
        hmac_key = hashlib.sha256(
            salt
        ).digest()

    actual_hmac = hmac.new(
        hmac_key,
        encrypted,
        hashlib.sha256,
    ).digest()

    if not hmac.compare_digest(
        expected_hmac,
        actual_hmac,
    ):
        raise ValueError(
            "HMAC не совпадает."
        )

    if flags & _FLAG_ENCRYPTED:
        encrypted = _decrypt(
            encrypted,
            encryption_password,
            salt,
            nonce,
        )

    return zlib.decompress(
        encrypted,
        max_length=1024 * 1024 * 1024,
    )


# ============================================================================
# PNG
# ============================================================================

def _load_image(path: str):
    """
    Загружает PNG без потери каналов.
    """
    img = Image.open(path)

    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA")

    pixels = np.array(
        img,
        dtype=np.uint8,
    )

    flat = pixels.flatten()

    return img, pixels, flat


# ============================================================================
# Публичный API
# ============================================================================

def hide(
    image_path: str,
    password: str,
    data: bytes,
    depth: int = 2,
    encryption_password: str | None = None,
) -> None:
    """
    Скрывает данные внутри PNG.
    """
    if not (1 <= depth <= 8):
        raise ValueError(
            "depth должен быть от 1 до 8."
        )

    payload = _build_payload(
        data,
        encryption_password,
    )

    img, pixels, flat = _load_image(
        image_path
    )

    sample = flat[:_SAMPLE_SIZE].tobytes()

    positions = _generate_map(
        password,
        sample,
        len(flat),
    )

    needed = _slots_needed(
        len(payload),
        depth,
    )

    if needed > len(positions):
        capacity = _capacity(
            len(positions),
            depth,
        )

        raise ValueError(
            f"Недостаточно места. "
            f"Максимум: {capacity} байт."
        )

    _write_bits(
        flat,
        positions,
        payload,
        depth,
    )

    Image.fromarray(
        pixels,
        mode=img.mode,
    ).save(
        image_path,
        "PNG",
    )


def extract(
    image_path: str,
    password: str,
    depth: int = 2,
    encryption_password: str | None = None,
) -> bytes:
    """
    Извлекает данные из PNG.
    """
    if not (1 <= depth <= 8):
        raise ValueError(
            "depth должен быть от 1 до 8."
        )

    _, _, flat = _load_image(
        image_path
    )

    sample = flat[:_SAMPLE_SIZE].tobytes()

    positions = _generate_map(
        password,
        sample,
        len(flat),
    )

    header = _read_bits(
        flat,
        positions,
        _HEADER_SIZE,
        depth,
    )

    if header[:4] != _MAGIC:
        raise ValueError(
            "Данные не найдены."
        )

    size = int.from_bytes(
        header[37:45],
        "big",
    )

    total_size = (
        _HEADER_SIZE + size
    )

    payload = _read_bits(
        flat,
        positions,
        total_size,
        depth,
    )

    return _parse_payload(
        payload,
        encryption_password,
    )
