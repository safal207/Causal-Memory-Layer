CREATE TABLE IF NOT EXISTS agent_memories (
    id UUID PRIMARY KEY,
    session_id STRING NOT NULL,
    kind STRING NOT NULL CHECK (kind IN ('observation', 'decision', 'outcome')),
    content STRING NOT NULL,
    tags JSONB NOT NULL DEFAULT '[]'::JSONB,
    status STRING NOT NULL DEFAULT 'active',
    confidence DECIMAL(5,4) NOT NULL DEFAULT 1.0,
    parent_memory_id UUID NULL REFERENCES agent_memories(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS agent_memories_session_created_idx
    ON agent_memories (session_id, created_at DESC);

CREATE INDEX IF NOT EXISTS agent_memories_status_idx
    ON agent_memories (session_id, status, created_at DESC);
