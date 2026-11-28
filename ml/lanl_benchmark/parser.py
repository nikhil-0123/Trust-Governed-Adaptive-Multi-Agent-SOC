"""
Streaming gzip parser for LANL Cyber1 authentication (`auth.txt.gz`) and
red-team annotation (`redteam.txt.gz`) files. Processes compressed streams line-by-line
without inflating multi-GB files onto disk.
"""

import gzip
import hashlib
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from .schema import LanlRawAuthEvent, LanlRedteamAnnotation


def _clean_lanl_token(val: str) -> Optional[str]:
    s = val.strip()
    if not s or s == "?":
        return None
    return s


def iter_lanl_auth_lines(
    lines: Iterable[str],
    stats: Optional[Dict[str, int]] = None,
    max_records: Optional[int] = None,
    compute_line_hash: bool = True,
    enforce_monotonic: bool = False,
) -> Iterator[LanlRawAuthEvent]:
    """
    Streams parsed `LanlRawAuthEvent` objects from lines matching LANL's 9-column format:
    `time, source_user@domain, destination_user@domain, source_computer, destination_computer, auth_type, logon_type, auth_orientation, success_failure`

    When `enforce_monotonic=True`, raises `ValueError` if any timestamp regresses below
    the previous valid event's `time_rel` (`time_rel < prev_time_rel`).
    """
    if stats is not None:
        stats.setdefault("lines_read", 0)
        stats.setdefault("valid_events", 0)
        stats.setdefault("malformed_lines", 0)

    emitted = 0
    prev_time_rel: Optional[int] = None
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if stats is not None:
            stats["lines_read"] += 1

        parts = stripped.split(",")
        if len(parts) != 9:
            if stats is not None:
                stats["malformed_lines"] += 1
            continue

        try:
            time_rel = int(parts[0].strip())
            if time_rel < 1:
                raise ValueError("time < 1")
        except ValueError:
            if stats is not None:
                stats["malformed_lines"] += 1
            continue

        outcome = parts[8].strip()
        if outcome not in ("Success", "Fail"):
            if stats is not None:
                stats["malformed_lines"] += 1
            continue

        if enforce_monotonic and prev_time_rel is not None and time_rel < prev_time_rel:
            raise ValueError(
                f"Non-monotonic timestamp regression in LANL auth stream at line {idx}: "
                f"time_rel={time_rel} < previous={prev_time_rel}"
            )
        prev_time_rel = time_rel

        line_hash = hashlib.sha256(stripped.encode("utf-8")).hexdigest()[:24] if compute_line_hash else stripped
        if stats is not None:
            stats["valid_events"] += 1

        emitted += 1
        yield LanlRawAuthEvent(
            record_seq=idx,
            time_rel=time_rel,
            source_user=_clean_lanl_token(parts[1]),
            destination_user=_clean_lanl_token(parts[2]),
            source_computer=_clean_lanl_token(parts[3]),
            destination_computer=_clean_lanl_token(parts[4]),
            auth_type=_clean_lanl_token(parts[5]),
            logon_type=_clean_lanl_token(parts[6]),
            auth_orientation=_clean_lanl_token(parts[7]),
            outcome=outcome,
            raw_line_hash=line_hash,
        )
        if max_records is not None and emitted >= max_records:
            return


def iter_lanl_auth_gz(
    gz_or_txt_path: Path,
    stats: Optional[Dict[str, int]] = None,
    max_records: Optional[int] = None,
    compute_line_hash: bool = True,
    enforce_monotonic: bool = False,
) -> Iterator[LanlRawAuthEvent]:
    opener = gzip.open if gz_or_txt_path.suffix == ".gz" else open
    with opener(gz_or_txt_path, "rt", encoding="utf-8", errors="replace") as f:
        yield from iter_lanl_auth_lines(
            f,
            stats=stats,
            max_records=max_records,
            compute_line_hash=compute_line_hash,
            enforce_monotonic=enforce_monotonic,
        )


def load_redteam_annotations_lines(lines: Iterable[str]) -> Tuple[List[LanlRedteamAnnotation], int]:
    """
    Parses LANL redteam 4-column lines:
    `time, user@domain, source_computer, destination_computer`
    Returns `(annotations, malformed_count)`.
    """
    out: List[LanlRedteamAnnotation] = []
    malformed = 0
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        parts = [p.strip() for p in stripped.split(",")]
        if len(parts) != 4:
            malformed += 1
            continue
        try:
            t_rel = int(parts[0])
            if t_rel < 1:
                raise ValueError("time < 1")
        except ValueError:
            malformed += 1
            continue
        if not parts[1] or not parts[2] or not parts[3]:
            malformed += 1
            continue
        out.append(
            LanlRedteamAnnotation(
                annotation_seq=idx,
                time_rel=t_rel,
                user_domain=parts[1],
                source_computer=parts[2],
                destination_computer=parts[3],
            )
        )
    return out, malformed


def load_redteam_annotations_gz(gz_or_txt_path: Path) -> Tuple[List[LanlRedteamAnnotation], int]:
    opener = gzip.open if gz_or_txt_path.suffix == ".gz" else open
    with opener(gz_or_txt_path, "rt", encoding="utf-8", errors="replace") as f:
        return load_redteam_annotations_lines(f)
