````markdown
# PNGHider

PNGHider — библиотека для скрытия данных внутри PNG-изображений через LSB-стеганографию.

Поддерживает:

- скрытие произвольных байтов
- пароль для генерации карты позиций
- опциональное шифрование вторым паролем
- HMAC-проверку целостности
- zlib-сжатие
- RGB и RGBA PNG

---

# Установка

```bash
pip install pillow numpy
````

---

# Как это работает

PNGHider записывает данные в младшие биты пикселей PNG.

Позиции записи:

* зависят от пароля
* псевдослучайно перемешиваются
* не используют начало изображения

Перед записью данные:

1. сжимаются через zlib
2. опционально шифруются
3. защищаются HMAC

---

# Пример

## Скрытие данных

```python
from PNGHider import hide

with open("secret.txt", "rb") as f:
    data = f.read()

hide(
    image_path="image.png",
    password="map-password",
    data=data,
)
```

---

## Извлечение данных

```python
from PNGHider import extract

data = extract(
    image_path="image.png",
    password="map-password",
)

print(data.decode())
```

---

# Шифрование

Можно дополнительно зашифровать данные отдельным паролем.

## Запись

```python
hide(
    image_path="image.png",
    password="map-password",
    encryption_password="encryption-password",
    data=b"Secret data",
)
```

## Чтение

```python
data = extract(
    image_path="image.png",
    password="map-password",
    encryption_password="encryption-password",
)
```

Если пароль неверный:

* HMAC не совпадёт
* будет выброшено исключение

---

# Параметр depth

```python
hide(..., depth=2)
```

depth определяет:

* сколько младших бит используется
* вместимость изображения
* заметность изменений

## Значения

| depth | Вместимость  | Незаметность |
| ----- | ------------ | ------------ |
| 1     | низкая       | высокая      |
| 2     | средняя      | высокая      |
| 4     | высокая      | средняя      |
| 8     | максимальная | очень низкая |

Рекомендуется:

```python
depth=1
```

или

```python
depth=2
```

---

# Вместимость изображения

Приблизительная вместимость:

```text
(width × height × channels × depth) / 8
```

Пример:

```text
1920 × 1080 × 3 × 2 / 8 ≈ 1.5 MB
```

---

# API

## hide

```python
hide(
    image_path: str,
    password: str,
    data: bytes,
    depth: int = 2,
    encryption_password: str | None = None,
) -> None
```

Скрывает данные внутри PNG.

### Аргументы

| Аргумент            | Описание             |
| ------------------- | -------------------- |
| image_path          | путь к PNG           |
| password            | пароль карты позиций |
| data                | данные для скрытия   |
| depth               | число LSB-бит        |
| encryption_password | пароль шифрования    |

---

## extract

```python
extract(
    image_path: str,
    password: str,
    depth: int = 2,
    encryption_password: str | None = None,
) -> bytes
```

Извлекает данные из PNG.

---

# Исключения

## Неверный пароль

```python
ValueError: HMAC не совпадает.
```

---

## Недостаточно места

```python
ValueError: Недостаточно места.
```

---

## Данные не найдены

```python
ValueError: Данные не найдены.
```

---

# Ограничения

* работает только с PNG
* PNG должен быть lossless
* изменение изображения разрушает скрытые данные
* ресайз/пересохранение обычно уничтожают payload

---

# Безопасность

PNGHider использует:

* PBKDF2-HMAC-SHA256
* SHA-512 stream cipher
* HMAC-SHA256
* zlib compression

Но это всё ещё стеганография, а не полноценная криптосистема.

Не используйте PNGHider как замену:

* PGP
* VeraCrypt
* age
* AES-GCM

---

# Лицензия

MIT

```
```
