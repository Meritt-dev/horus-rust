-- A few rows in the legacy user-run Postgres schema (packages/db/drizzle 0000-0015), for
-- `horus db import --from postgres://…/horus_legacy`. Fixed ids so re-imports upsert.
INSERT INTO investigations (id, title, incident_input, status, summary, narrative, created_at, updated_at, project) VALUES
 ('11111111-1111-4111-8111-111111111111', 'Checkout 502s after deploy', '{"hint":"checkout 502 spike","service":"api"}', 'resolved',
  'Payment client timeout lowered in v2.3.1', '{"verdict":"confirmed"}', '2026-09-01T10:00:00Z', '2026-09-01T11:30:00Z', 'shop'),
 ('22222222-2222-4222-8222-222222222222', 'Inventory sync stuck', '{"hint":"inventory sync stuck since 02:00"}', 'open',
  NULL, NULL, '2026-10-01T02:15:00.123Z', '2026-10-01T02:20:00Z', 'shop');

INSERT INTO evidence (id, investigation_id, source, kind, title, "timestamp", relevance, payload, links, provenance, created_at) VALUES
 ('aaaaaaa1-0000-4000-8000-000000000001', '11111111-1111-4111-8111-111111111111', 'elasticsearch', 'log', '502 from payments', '2026-09-01T09:58:00Z', 0.9,
  '{"count":412,"sample":"upstream timed out"}', '["https://logs.example/1"]', '{"query":"status:502"}', '2026-09-01T10:01:00Z'),
 ('aaaaaaa1-0000-4000-8000-000000000002', '11111111-1111-4111-8111-111111111111', 'git', 'change', 'v2.3.1 deploy', NULL, 0.5, NULL, NULL, NULL, '2026-09-01T10:02:00Z');

INSERT INTO findings (id, investigation_id, kind, title, detail, confidence, evidence_ids, created_at) VALUES
 ('bbbbbbb1-0000-4000-8000-000000000001', '11111111-1111-4111-8111-111111111111', 'cause', 'Timeout lowered to 2s', 'payments p99 is 2.4s', 0.75,
  '{aaaaaaa1-0000-4000-8000-000000000001,aaaaaaa1-0000-4000-8000-000000000002}', '2026-09-01T10:05:00Z');

INSERT INTO hypotheses (id, investigation_id, rank, statement, score, supporting_evidence, created_at) VALUES
 ('ccccccc1-0000-4000-8000-000000000001', '11111111-1111-4111-8111-111111111111', 1, 'Deploy lowered payment timeout', 0.8,
  '{aaaaaaa1-0000-4000-8000-000000000001}', '2026-09-01T10:06:00Z'),
 ('ccccccc1-0000-4000-8000-000000000002', '22222222-2222-4222-8222-222222222222', 1, 'Upstream inventory API returning 502', 0.4, NULL, '2026-10-01T02:16:00Z');

INSERT INTO incident_memory (id, investigation_id, title, summary, signature, tags, payload, created_at) VALUES
 ('ddddddd1-0000-4000-8000-000000000001', '11111111-1111-4111-8111-111111111111', 'Checkout 502s', 'timeout regression', 'sig:checkout-502',
  '{checkout,payments}', '{"service":"api"}', '2026-09-01T11:30:00Z');

INSERT INTO outcome_label (id, investigation_id, project, resolved, confirmed_cause, note, source, payload, at) VALUES
 ('eeeeeee1-0000-4000-8000-000000000001', '11111111-1111-4111-8111-111111111111', 'shop', 'confirmed', 'Deploy lowered payment timeout', 'rolled back', 'cli', NULL, '2026-09-01T12:00:00Z');

INSERT INTO memory_item (id, kind, claim, scope, source, evidence, confidence, status, created_at, repo, visibility) VALUES
 ('mem-legacy-1', 'fact', 'Payments client timeout must stay above p99 latency', 'repo', 'investigation',
  '[{"investigationId":"11111111-1111-4111-8111-111111111111"}]', 0.9, 'fresh', '2026-09-02T08:00:00Z', 'shop-api', 'private');

INSERT INTO memory_link (id, from_memory_id, rel, to_kind, to_ref, to_file_path, created_at) VALUES
 ('link-legacy-1', 'mem-legacy-1', 'about', 'file', 'src/payments/client.ts', 'src/payments/client.ts', '2026-09-02T08:00:00Z');

INSERT INTO memory_audit (id, memory_id, action, actor, from_status, to_status, note, at) VALUES
 ('audit-legacy-1', 'mem-legacy-1', 'create', '{"kind":"user","id":"local"}', NULL, 'fresh', 'seeded', '2026-09-02T08:00:00Z');
