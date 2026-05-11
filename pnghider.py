"""
PNGHider — стеганография в PNG-изображениях.

Данные скрываются в младших битах байтов пикселей.
Порядок позиций определяется паролем, что обеспечивает базовую защиту.

Формат встроенного блока данных:
    байт 0       — N, число байт под поле размера (1..4)
    байты 1..N   — размер сжатых данных (big-endian)
    байты N+1..  — zlib-сжатые исходные данные

Основные функции:
    hide    — спрятать данные в PNG
    extract — извлечь данные из PNG
"""

import hashlib
import random
import zlib

import numpy as np
from PIL import Image


# ---------------------------------------------------------------------------
# Внутренние константы
# ---------------------------------------------------------------------------

_STEP         = 3     # каждый STEP-й байт хранит одну группу бит
_SAMPLE_SIZE  = 1024  # размер зоны, по которой вычисляется seed
_SAMPLE_GUARD = _SAMPLE_SIZE  # позиции до этой границы исключаются из карты
_MAX_N        = 4     # максимум байт под поле «размер архива»


# ---------------------------------------------------------------------------
# Заголовок блока данных
# ---------------------------------------------------------------------------

def _encode_header(data_len: int) -> bytes:
    """Строит самоописывающий заголовок (N + data_len в big-endian)."""
    for n in range(1, _MAX_N + 1):
        if data_len < (1 << (n * 8)):
            return bytes([n]) + data_len.to_bytes(n, "big")
    raise ValueError(f"Данные слишком велики: {data_len} байт.")


def _decode_header(raw: bytes) -> tuple[int, int]:
    """
    Разбирает заголовок из байтовой строки.
    Возвращает (data_len, полный_размер_заголовка).
    """
    if not raw:
        raise ValueError("Пустой буфер — невозможно прочитать заголовок.")
    n = raw[0]
    if n < 1 or n > _MAX_N:
        raise ValueError(
            f"Некорректный заголовок (N={n}). "
            "Неверный пароль или повреждённое изображение."
        )
    if len(raw) < 1 + n:
        raise ValueError("Буфер обрезан — заголовок неполный.")
    return int.from_bytes(raw[1 : 1 + n], "big"), 1 + n


# ---------------------------------------------------------------------------
# Карта позиций
# ---------------------------------------------------------------------------

def _generate_map(
    password: str,
    pixel_sample: bytes,
    total_bytes: int,
    step: int = _STEP,
) -> list[int]:
    """
    Возвращает перемешанный список байтовых позиций для записи/чтения.

    Seed получается из пароля и первых SAMPLE_SIZE байт пикселей,
    которые не изменяются в процессе записи (зона сэмпла).
    Позиции внутри этой зоны исключаются.
    """
    slots = total_bytes // step
    if slots == 0:
        raise ValueError("Изображение слишком маленькое.")

    seed = int.from_bytes(
        hashlib.sha512(password.encode() + pixel_sample).digest()[:8],
        "big",
    )
    rng = random.Random(seed)
    indices = list(range(slots))
    rng.shuffle(indices)

    return [i * step for i in indices if i * step >= _SAMPLE_GUARD]


def _slots_needed(byte_count: int, depth: int) -> int:
    """Количество позиций, необходимых для хранения byte_count байт."""
    return -(-byte_count * 8 // depth)  # ceil(byte_count*8 / depth)


# ---------------------------------------------------------------------------
# Запись и чтение битов
# ---------------------------------------------------------------------------

def _write_bits(
    pixels: np.ndarray,
    positions: list[int],
    data: bytes,
    depth: int,
) -> None:
    """Записывает data в младшие depth бит пикселей по карте positions."""
    bits = bin(int.from_bytes(data, "big"))[2:].zfill(len(data) * 8)
    mask_clear = 0xFF ^ ((1 << depth) - 1)
    needed = _slots_needed(len(data), depth)

    for bit_pos, pos in zip(range(0, len(bits), depth), positions[:needed]):
        if pos >= len(pixels):
            raise IndexError(f"Позиция {pos} выходит за пределы массива.")
        chunk = bits[bit_pos : bit_pos + depth].ljust(depth, "0")
        pixels[pos] = (pixels[pos] & mask_clear) | int(chunk, 2)


def _read_bits(
    pixels: np.ndarray,
    positions: list[int],
    depth: int,
) -> bytes:
    """Читает младшие depth бит по карте positions и возвращает байты."""
    mask = (1 << depth) - 1
    bits = "".join(
        f"{pixels[p] & mask:0{depth}b}"
        for p in positions
        if p < len(pixels)
    )
    usable = (len(bits) // 8) * 8
    return bytes(int(bits[i : i + 8], 2) for i in range(0, usable, 8))


# ---------------------------------------------------------------------------
# Внутренняя однофайловая запись / чтение
# ---------------------------------------------------------------------------

def _image_capacity(image_path: str, depth: int) -> int:
    """Возвращает число байт, которое вмещает изображение при данном depth."""
    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img, dtype=np.uint8).flatten()
    pos_map = _generate_map("_", pixels[:_SAMPLE_SIZE].tobytes(), len(pixels))
    return len(pos_map) * depth // 8


def _hide_single(image_path: str, password: str, payload: bytes, depth: int) -> None:
    """Записывает готовый payload (уже с заголовком) в один PNG."""
    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img, dtype=np.uint8).flatten()
    sample = pixels[:_SAMPLE_SIZE].tobytes()
    pos_map = _generate_map(password, sample, len(pixels))
    needed = _slots_needed(len(payload), depth)
    if needed > len(pos_map):
        raise ValueError(
            f"Данные не помещаются: нужно {needed} позиций, "
            f"доступно {len(pos_map)}."
        )
    _write_bits(pixels, pos_map[:needed], payload, depth)
    Image.fromarray(pixels.reshape(img.height, img.width, 3)).save(
        image_path, "PNG", compress_level=0
    )


def _extract_single(image_path: str, password: str, depth: int) -> bytes:
    """Читает payload (с заголовком) из одного PNG и возвращает исходные байты."""
    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img, dtype=np.uint8).flatten()
    sample = pixels[:_SAMPLE_SIZE].tobytes()
    pos_map = _generate_map(password, sample, len(pixels))

    h_raw = _read_bits(pixels, pos_map[:_slots_needed(1 + _MAX_N, depth)], depth)
    data_len, header_size = _decode_header(h_raw)

    total = header_size + data_len
    raw = _read_bits(pixels, pos_map[:_slots_needed(total, depth)], depth)
    return zlib.decompress(raw[header_size : header_size + data_len])


# ---------------------------------------------------------------------------
# Многофайловый заголовок чанка
# ---------------------------------------------------------------------------
#
# Каждый PNG при многофайловой записи хранит один чанк со своим заголовком:
#   4 байта — общее число чанков (big-endian)
#   4 байта — индекс этого чанка (0-based, big-endian)
#   4 байта — длина данных чанка
#   далее   — zlib-сжатые данные всего сообщения (только своя часть)
#
# Однофайловый режим использует старый формат (_encode_header / _decode_header),
# многофайловый — _CHUNK_HEADER_SIZE байт выше.

_CHUNK_HEADER_SIZE = 12  # 3 × uint32


def _encode_chunk_header(total_chunks: int, index: int, chunk_len: int) -> bytes:
    return (
        total_chunks.to_bytes(4, "big")
        + index.to_bytes(4, "big")
        + chunk_len.to_bytes(4, "big")
    )


def _decode_chunk_header(raw: bytes) -> tuple[int, int, int]:
    """Возвращает (total_chunks, index, chunk_len)."""
    if len(raw) < _CHUNK_HEADER_SIZE:
        raise ValueError("Буфер слишком мал для чтения заголовка чанка.")
    total  = int.from_bytes(raw[0:4], "big")
    index  = int.from_bytes(raw[4:8], "big")
    length = int.from_bytes(raw[8:12], "big")
    return total, index, length


# ---------------------------------------------------------------------------
# Публичный API
# ---------------------------------------------------------------------------

def hide(
    image_paths: "str | list[str]",
    password: str,
    data: bytes,
    depth: int = 2,
) -> None:
    """
    Спрятать данные в одном или нескольких PNG-изображениях.

    Если данные не влезают в переданные файлы, функция интерактивно
    запрашивает пути к дополнительным PNG до тех пор, пока места не хватит.

    Parameters
    ----------
    image_paths : путь к PNG или список путей
    password    : пароль; нужен при извлечении
    data        : произвольные байты для сокрытия
    depth       : 1–8; бит на канал (больше → ёмкость ↑, незаметность ↓)
    """
    if not (1 <= depth <= 8):
        raise ValueError("depth должен быть от 1 до 8.")

    # Нормализуем к списку
    paths: list[str] = [image_paths] if isinstance(image_paths, str) else list(image_paths)

    compressed = zlib.compress(data)

    # --- Однофайловый режим (старый формат, без чанков) ---
    if len(paths) == 1:
        payload = _encode_header(len(compressed)) + compressed
        needed  = _slots_needed(len(payload), depth)

        img     = Image.open(paths[0]).convert("RGB")
        pixels  = np.array(img, dtype=np.uint8).flatten()
        sample  = pixels[:_SAMPLE_SIZE].tobytes()
        pos_map = _generate_map(password, sample, len(pixels))

        if needed <= len(pos_map):
            _write_bits(pixels, pos_map[:needed], payload, depth)
            Image.fromarray(pixels.reshape(img.height, img.width, 3)).save(
                paths[0], "PNG", compress_level=0
            )
            return

        # Одного файла не хватило — переходим в многофайловый режим
        print(f"'{paths[0]}' слишком мал. Переключаюсь на многофайловый режим.")

    # --- Многофайловый режим ---
    # Сначала узнаём вместимость каждого файла (без учёта заголовка чанка)
    def usable_capacity(path: str) -> int:
        img    = Image.open(path).convert("RGB")
        px     = np.array(img, dtype=np.uint8).flatten()
        sample = px[:_SAMPLE_SIZE].tobytes()
        pm     = _generate_map(password, sample, len(px))
        # Вычитаем место под заголовок чанка
        return max(0, len(pm) * depth // 8 - _CHUNK_HEADER_SIZE)

    # Набираем файлы до тех пор, пока суммарная ёмкость не покроет данные
    while sum(usable_capacity(p) for p in paths) < len(compressed):
        used  = sum(usable_capacity(p) for p in paths)
        remain = len(compressed) - used
        print(
            f"Недостаточно места: нужно ещё ~{remain} байт сжатых данных. "
            f"Уже используется файлов: {len(paths)}."
        )
        new_path = input("Введите путь к ещё одному PNG: ").strip()
        if not new_path:
            raise ValueError("Путь не введён — операция прервана.")
        paths.append(new_path)

    # Нарезаем compressed на чанки по ёмкости каждого файла
    total_chunks = len(paths)
    offset = 0
    for idx, path in enumerate(paths):
        cap   = usable_capacity(path)
        chunk = compressed[offset : offset + cap]
        offset += cap

        payload = _encode_chunk_header(total_chunks, idx, len(chunk)) + chunk
        _hide_single(path, password, payload, depth)

    print(f"Данные распределены по {total_chunks} файл(ам).")


def extract(
    image_paths: "str | list[str]",
    password: str,
    depth: int = 2,
) -> bytes:
    """
    Извлечь данные, спрятанные функцией hide().

    Автоматически определяет однофайловый или многофайловый формат.
    При многофайловой записи порядок файлов в списке не важен —
    чанки собираются по индексам из заголовков.

    Parameters
    ----------
    image_paths : путь к PNG или список путей
    password    : должен совпадать с использованным при записи
    depth       : должен совпадать с использованным при записи

    Returns
    -------
    bytes : исходные данные
    """
    if not (1 <= depth <= 8):
        raise ValueError("depth должен быть от 1 до 8.")

    paths: list[str] = [image_paths] if isinstance(image_paths, str) else list(image_paths)

    if len(paths) == 1:
        # Пробуем однофайловый формат; если заголовок не распознан — многофайловый
        try:
            return _extract_single(paths[0], password, depth)
        except ValueError:
            pass  # возможно, файл записан в многофайловом формате

    # --- Многофайловый режим ---
    chunks: dict[int, bytes] = {}
    total_chunks_expected: int | None = None

    for path in paths:
        img     = Image.open(path).convert("RGB")
        pixels  = np.array(img, dtype=np.uint8).flatten()
        sample  = pixels[:_SAMPLE_SIZE].tobytes()
        pos_map = _generate_map(password, sample, len(pixels))

        # Читаем заголовок чанка
        h_slots = _slots_needed(_CHUNK_HEADER_SIZE, depth)
        h_raw   = _read_bits(pixels, pos_map[:h_slots], depth)
        total_chunks, index, chunk_len = _decode_chunk_header(h_raw)

        if total_chunks_expected is None:
            total_chunks_expected = total_chunks
        elif total_chunks != total_chunks_expected:
            raise ValueError(
                f"Файл '{path}': ожидалось {total_chunks_expected} чанков, "
                f"получено {total_chunks}. Файлы из разных наборов?"
            )

        # Читаем тело чанка
        total_payload = _CHUNK_HEADER_SIZE + chunk_len
        full_raw = _read_bits(pixels, pos_map[:_slots_needed(total_payload, depth)], depth)
        chunks[index] = full_raw[_CHUNK_HEADER_SIZE : _CHUNK_HEADER_SIZE + chunk_len]

    if total_chunks_expected is None:
        raise ValueError("Не передано ни одного файла.")

    missing = set(range(total_chunks_expected)) - set(chunks)
    if missing:
        raise ValueError(f"Отсутствуют чанки с индексами: {sorted(missing)}.")

    compressed = b"".join(chunks[i] for i in range(total_chunks_expected))
    return zlib.decompress(compressed)
