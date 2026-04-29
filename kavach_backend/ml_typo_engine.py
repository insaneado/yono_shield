"""Fast ML-style typo-squatting similarity engine for KAVACH.

The production scanner uses a character-level TF-IDF model because it is fast,
deterministic, and good at catching sub-word overlap in visual/phonetic
typosquats such as ``sttebank`` vs ``statebank``.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


@dataclass(frozen=True)
class TypoSimilarityResult:
    is_match: bool
    score: float
    protected_domain: str | None
    rule: str | None


class TypoSimilarityEngine:
    """Character n-gram TF-IDF + cosine similarity typo detector."""

    def __init__(
        self,
        protected_domains: list[str],
        *,
        threshold: float = 0.85,
        ngram_range: tuple[int, int] = (2, 4),
    ) -> None:
        if not protected_domains:
            raise ValueError("protected_domains must contain at least one domain")

        self.threshold = threshold
        self.protected_domains = [_normalize_domain(d) for d in protected_domains]
        self._vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            lowercase=True,
            ngram_range=ngram_range,
            norm="l2",
        )
        self._protected_matrix = self._vectorizer.fit_transform(self.protected_domains)

    def score(self, domain: str) -> TypoSimilarityResult:
        normalized_domain = _normalize_domain(domain)
        if not normalized_domain:
            return TypoSimilarityResult(False, 0.0, None, None)

        incoming_vector = self._vectorizer.transform([normalized_domain])
        similarities = cosine_similarity(
            incoming_vector,
            self._protected_matrix,
        )[0]
        best_index = int(similarities.argmax())
        best_score = float(similarities[best_index])
        protected_domain = self.protected_domains[best_index]

        if best_score > self.threshold:
            return TypoSimilarityResult(
                is_match=True,
                score=best_score,
                protected_domain=protected_domain,
                rule=(
                    f"TYPOSQUAT_DETECTED: '{normalized_domain}' has "
                    f"{best_score:.0%} character n-gram similarity to "
                    f"protected asset '{protected_domain}'"
                ),
            )

        return TypoSimilarityResult(
            is_match=False,
            score=best_score,
            protected_domain=protected_domain,
            rule=None,
        )


def _normalize_domain(value: str) -> str:
    """Convert URLs/domains to a stable ASCII domain token."""
    text = (value or "").strip().lower()
    if not text:
        return ""

    parsed = urlparse(text if "://" in text else f"https://{text}")
    domain = (parsed.netloc or parsed.path).split("/")[0].split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]

    return domain.encode("ascii", errors="ignore").decode("ascii")
