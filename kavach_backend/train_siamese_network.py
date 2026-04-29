"""PyTorch Siamese 1D-CNN architecture for domain similarity training.

This script intentionally contains the model and tensorization pieces only.
Training data construction can be plugged in later with positive pairs such as
(``statebankofindia.com``, ``sttebankofindia.com``) and negative unrelated
domain pairs.
"""

from __future__ import annotations

import string

import torch
from torch import nn
from torch.nn import functional as F


ALPHABET = string.ascii_lowercase + string.digits + ".-"
PAD_INDEX = 0
CHAR_TO_INDEX = {char: index + 1 for index, char in enumerate(ALPHABET)}
VOCAB_SIZE = len(CHAR_TO_INDEX) + 1


def domain_to_tensor(domain: str, max_length: int = 96) -> torch.Tensor:
    """Encode a domain string as a fixed-length ASCII character tensor."""
    normalized = domain.lower().encode("ascii", errors="ignore").decode("ascii")
    indices = [CHAR_TO_INDEX.get(char, PAD_INDEX) for char in normalized[:max_length]]
    indices.extend([PAD_INDEX] * (max_length - len(indices)))
    return torch.tensor(indices, dtype=torch.long)


class DomainEncoder(nn.Module):
    """Lightweight 1D-CNN encoder for ASCII domain strings."""

    def __init__(
        self,
        vocab_size: int = VOCAB_SIZE,
        embedding_dim: int = 32,
        hidden_channels: int = 96,
        output_dim: int = 128,
    ) -> None:
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=PAD_INDEX)
        self.conv_stack = nn.Sequential(
            nn.Conv1d(embedding_dim, hidden_channels, kernel_size=3, padding=1),
            nn.BatchNorm1d(hidden_channels),
            nn.ReLU(),
            nn.Conv1d(hidden_channels, hidden_channels, kernel_size=5, padding=2),
            nn.BatchNorm1d(hidden_channels),
            nn.ReLU(),
            nn.AdaptiveMaxPool1d(1),
        )
        self.projection = nn.Sequential(
            nn.Linear(hidden_channels, output_dim),
            nn.ReLU(),
            nn.Linear(output_dim, output_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        embedded = self.embedding(x).transpose(1, 2)
        features = self.conv_stack(embedded).squeeze(-1)
        return F.normalize(self.projection(features), p=2, dim=1)


class SiameseDomainNetwork(nn.Module):
    """Outputs a similarity score in [0, 1] for two domain tensors."""

    def __init__(self, encoder: DomainEncoder | None = None) -> None:
        super().__init__()
        self.encoder = encoder or DomainEncoder()
        self.classifier = nn.Sequential(
            nn.Linear(128 * 3, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 1),
            nn.Sigmoid(),
        )

    def forward(self, left: torch.Tensor, right: torch.Tensor) -> torch.Tensor:
        left_embedding = self.encoder(left)
        right_embedding = self.encoder(right)
        pair_features = torch.cat(
            [
                left_embedding,
                right_embedding,
                torch.abs(left_embedding - right_embedding),
            ],
            dim=1,
        )
        return self.classifier(pair_features).squeeze(1)


if __name__ == "__main__":
    model = SiameseDomainNetwork()
    left = domain_to_tensor("statebankofindia.com").unsqueeze(0)
    right = domain_to_tensor("sttebankofindia.com").unsqueeze(0)
    with torch.no_grad():
        score = model(left, right).item()
    print(f"Untrained similarity score: {score:.4f}")
