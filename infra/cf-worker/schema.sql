-- D1 schema for quill telemetry receiver.
-- Apply with:  wrangler d1 execute quill-telemetry --file ./schema.sql

CREATE TABLE IF NOT EXISTS events (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  received_at     TEXT NOT NULL,
  schema_version  INTEGER NOT NULL,
  install_id      TEXT NOT NULL,
  quill_version   TEXT NOT NULL,
  py_version      TEXT NOT NULL,
  os              TEXT NOT NULL,
  event           TEXT NOT NULL,
  data            TEXT NOT NULL  -- json blob; aggregate counts only
);

CREATE INDEX IF NOT EXISTS idx_events_received_at ON events(received_at);
CREATE INDEX IF NOT EXISTS idx_events_quill_version ON events(quill_version);
CREATE INDEX IF NOT EXISTS idx_events_event ON events(event);
