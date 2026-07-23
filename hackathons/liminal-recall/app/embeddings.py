from __future__ import annotations

import json
import os
from typing import Any, Protocol


DEFAULT_MODEL_ID = "amazon.titan-embed-text-v2:0"
DEFAULT_DIMENSIONS = 256
SUPPORTED_DIMENSIONS = {256, 512, 1024}


class Embedder(Protocol):
    model_id: str
    dimensions: int

    def embed(self, text: str) -> list[float]: ...


class BedrockTitanEmbedder:
    """Generate normalized Titan Text Embeddings V2 vectors through Bedrock."""

    def __init__(
        self,
        model_id: str = DEFAULT_MODEL_ID,
        dimensions: int = DEFAULT_DIMENSIONS,
        region_name: str | None = None,
        client: Any | None = None,
    ) -> None:
        if dimensions not in SUPPORTED_DIMENSIONS:
            raise ValueError("embedding dimensions must be one of 256, 512, or 1024")
        self.model_id = model_id
        self.dimensions = dimensions
        self.region_name = region_name
        self._client = client

    @classmethod
    def from_env(cls) -> "BedrockTitanEmbedder":
        dimensions = int(os.getenv("EMBEDDING_DIMENSIONS", str(DEFAULT_DIMENSIONS)))
        region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
        return cls(
            model_id=os.getenv("EMBEDDING_MODEL_ID", DEFAULT_MODEL_ID),
            dimensions=dimensions,
            region_name=region,
        )

    def embed(self, text: str) -> list[float]:
        normalized = " ".join(text.split())
        if not normalized:
            raise ValueError("embedding input must not be empty")

        client = self._client
        if client is None:
            import boto3

            client = boto3.client("bedrock-runtime", region_name=self.region_name)
            self._client = client

        response = client.invoke_model(
            modelId=self.model_id,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(
                {
                    "inputText": normalized,
                    "dimensions": self.dimensions,
                    "normalize": True,
                    "embeddingTypes": ["float"],
                }
            ),
        )
        payload = json.loads(response["body"].read())
        vector = payload.get("embedding")
        if not isinstance(vector, list) or len(vector) != self.dimensions:
            raise RuntimeError("Bedrock returned an invalid embedding vector")
        return [float(value) for value in vector]


def memory_embedding_text(content: str, tags: list[str]) -> str:
    tag_text = ", ".join(tags) if tags else "none"
    return f"Memory: {content}\nTags: {tag_text}"
