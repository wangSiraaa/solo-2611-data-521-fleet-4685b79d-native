"""Strict validation of the fixed ``id,value`` CSV import contract.

Validation is complete before any database write, so a malformed row can never
leave a prefix of rows behind.  The rules are:

* the whole object must decode as UTF-8;
* the header is exactly ``id,value``;
* every data row has exactly two fields;
* ``id`` is non-empty and unique within the file;
* ``value`` is a decimal non-negative integer that fits in signed int64;
* at most 1000 data rows.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass

from .errors import CsvValidationError

MAX_ROWS = 1000
INT64_MAX = (1 << 63) - 1
_DIGITS = re.compile(r"^[0-9]+$")
_BOOL_WORDS = {"true", "false", "t", "f", "yes", "no"}


@dataclass(frozen=True)
class CsvRow:
    id: str
    value: int


def parse_csv(data: bytes) -> list[CsvRow]:
    """Return validated rows or raise :class:`CsvValidationError`."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CsvValidationError("DECODE_ERROR", str(exc)) from exc

    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        header = next(reader)
    except StopIteration:
        raise CsvValidationError("EMPTY_FILE", "missing header")
    except csv.Error as exc:
        raise CsvValidationError("CSV_SYNTAX", str(exc)) from exc

    if header != ["id", "value"]:
        raise CsvValidationError(
            "BAD_HEADER", f"expected ['id', 'value'], got {header!r}"
        )

    rows: list[CsvRow] = []
    seen: set[str] = set()
    try:
        for fields in reader:
            if len(fields) != 2:
                # An empty line is reported as [] and is malformed here.
                raise CsvValidationError(
                    "BAD_COLUMN_COUNT",
                    f"row {len(rows) + 2} has {len(fields)} field(s), expected 2",
                )
            raw_id, raw_value = fields
            if raw_id == "":
                raise CsvValidationError(
                    "EMPTY_ID", f"row {len(rows) + 2} has an empty id"
                )
            if raw_id in seen:
                raise CsvValidationError(
                    "DUPLICATE_ID", f"row {len(rows) + 2} repeats id {raw_id!r}"
                )
            if raw_value == "" or not _DIGITS.match(raw_value):
                # Reject booleans explicitly (e.g. "true"/"false") as well as
                # signs, whitespace, floats and other non-integer spellings.
                raise CsvValidationError(
                    "BAD_VALUE",
                    f"row {len(rows) + 2} value {raw_value!r} is not a non-negative integer",
                )
            if raw_value.lower() in _BOOL_WORDS:  # defensive; unreachable for digits
                raise CsvValidationError(
                    "BAD_VALUE", f"row {len(rows) + 2} value {raw_value!r} is boolean"
                )
            value = int(raw_value)
            if value > INT64_MAX:
                raise CsvValidationError(
                    "VALUE_OUT_OF_RANGE",
                    f"row {len(rows) + 2} value {raw_value} exceeds int64",
                )
            seen.add(raw_id)
            rows.append(CsvRow(raw_id, value))
            if len(rows) > MAX_ROWS:
                raise CsvValidationError(
                    "TOO_MANY_ROWS", f"more than {MAX_ROWS} data rows"
                )
    except csv.Error as exc:
        raise CsvValidationError("CSV_SYNTAX", str(exc)) from exc

    return rows
