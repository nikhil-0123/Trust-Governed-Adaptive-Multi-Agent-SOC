"""
Exact-Match Red-Team Annotation Join with Duplicate & Ambiguity Audits.

Implements documented LANL Cyber1 join semantics `(time, user@domain, source_computer, destination_computer)`
while tracking annotation multiplicity, duplicate annotations, and ambiguous 1-second bucket collisions.
Does NOT reinterpret unmatched records as verified clean benign ground truth.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .schema import LanlRawAuthEvent, LanlRedteamAnnotation


class MatchStatus(str, Enum):
    EXACT_UNIQUE_MATCH = "EXACT_UNIQUE_MATCH"
    AMBIGUOUS_MULTI_MATCH = "AMBIGUOUS_MULTI_MATCH"
    UNMATCHED_NON_REDTEAM = "UNMATCHED_NON_REDTEAM"


@dataclass(frozen=True)
class RedteamJoinResult:
    status: str
    label: int  # 1 if matched redteam annotation, 0 otherwise
    label_source: str
    match_multiplicity: int
    annotation_duplicate_count: int
    is_ambiguous: bool
    matched_user_field: Optional[str] = None


class RedteamAnnotationIndex:
    """
    Memory-efficient lookup index over LANL Cyber1 `redteam.txt.gz` annotations.
    Key = `(time_rel, user_domain, source_computer, destination_computer)`.
    """

    def __init__(self, annotations: Sequence[LanlRedteamAnnotation]):
        self.total_annotations = len(annotations)
        self._key_counts: Dict[Tuple[int, str, str, str], int] = {}
        self._matched_keys: Set[Tuple[int, str, str, str]] = set()
        self._auth_hits_per_key: Dict[Tuple[int, str, str, str], int] = {}

        for ann in annotations:
            k = (ann.time_rel, ann.user_domain, ann.source_computer, ann.destination_computer)
            self._key_counts[k] = self._key_counts.get(k, 0) + 1

        self.unique_annotation_keys = len(self._key_counts)
        self.duplicate_annotation_count = self.total_annotations - self.unique_annotation_keys

    def match_event(self, ev: LanlRawAuthEvent, precomputed_key_hits: Optional[int] = None) -> RedteamJoinResult:
        """
        Matches a single LANL auth event against the redteam index.
        Checks both `destination_user` and `source_user` cleanly.
        """
        if not ev.source_computer or not ev.destination_computer:
            return RedteamJoinResult(
                status=MatchStatus.UNMATCHED_NON_REDTEAM.value,
                label=0,
                label_source="unmatched_missing_host_fields",
                match_multiplicity=0,
                annotation_duplicate_count=0,
                is_ambiguous=False,
            )

        candidate_keys: List[Tuple[str, Tuple[int, str, str, str]]] = []
        if ev.destination_user:
            candidate_keys.append(
                ("destination_user", (ev.time_rel, ev.destination_user, ev.source_computer, ev.destination_computer))
            )
        if ev.source_user and ev.source_user != ev.destination_user:
            candidate_keys.append(
                ("source_user", (ev.time_rel, ev.source_user, ev.source_computer, ev.destination_computer))
            )

        hits = [(fld, k, self._key_counts[k]) for fld, k in candidate_keys if k in self._key_counts]
        if not hits:
            return RedteamJoinResult(
                status=MatchStatus.UNMATCHED_NON_REDTEAM.value,
                label=0,
                label_source="unmatched_background_not_in_redteam",
                match_multiplicity=0,
                annotation_duplicate_count=0,
                is_ambiguous=False,
            )

        # Record matched state
        matched_fields = [h[0] for h in hits]
        primary_key = hits[0][1]
        ann_dup_count = max(0, hits[0][2] - 1)
        self._matched_keys.add(primary_key)
        self._auth_hits_per_key[primary_key] = self._auth_hits_per_key.get(primary_key, 0) + 1
        observed_hits = precomputed_key_hits if precomputed_key_hits is not None else self._auth_hits_per_key[primary_key]

        is_ambig = (observed_hits > 1) or (len(hits) > 1) or (hits[0][2] > 1)
        status = MatchStatus.AMBIGUOUS_MULTI_MATCH.value if is_ambig else MatchStatus.EXACT_UNIQUE_MATCH.value

        return RedteamJoinResult(
            status=status,
            label=1,
            label_source="lanl_redteam_exact_match",
            match_multiplicity=observed_hits,
            annotation_duplicate_count=ann_dup_count,
            is_ambiguous=is_ambig,
            matched_user_field="+".join(matched_fields),
        )

    @property
    def unmatched_annotation_keys(self) -> Set[Tuple[int, str, str, str]]:
        return set(self._key_counts.keys()) - self._matched_keys
