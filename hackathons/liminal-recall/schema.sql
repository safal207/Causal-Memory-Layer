SET CLUSTER SETTING feature.vector_index.enabled = true;
SET sql_safe_updates = false;

CREATE TABLE IF NOT EXISTS agent_memories (
    id UUID PRIMARY KEY,
    session_id STRING NOT NULL,
    kind STRING NOT NULL CHECK (kind IN ('observation', 'decision', 'outcome')),
    content STRING NOT NULL,
    tags JSONB NOT NULL DEFAULT '[]'::JSONB,
    status STRING NOT NULL DEFAULT 'active',
    confidence DECIMAL(5,4) NOT NULL DEFAULT 1.0 CHECK (confidence >= 0 AND confidence <= 1),
    parent_memory_id UUID NULL REFERENCES agent_memories(id),
    embedding VECTOR(256) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Allows the schema to upgrade an earlier non-vector scaffold in place.
ALTER TABLE agent_memories
    ADD COLUMN IF NOT EXISTS embedding VECTOR(256) NULL;

CREATE INDEX IF NOT EXISTS agent_memories_session_created_idx
    ON agent_memories (session_id, created_at DESC);

CREATE INDEX IF NOT EXISTS agent_memories_status_idx
    ON agent_memories (session_id, status, created_at DESC);

-- Prefix columns match the exact filters in semantic recall queries, allowing
-- CockroachDB's distributed vector index to search only the relevant session
-- and verified-negative outcome partition.
CREATE VECTOR INDEX IF NOT EXISTS agent_memories_semantic_idx
    ON agent_memories (
        session_id,
        kind,
        status,
        embedding vector_cosine_ops
    );
