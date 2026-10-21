-- App-shaped tables for `horus state` (postgres connector). Dates are relative to now() so the
-- classifications stay stable: orders = stale (last update 3 days ago), sync_jobs = active with
-- failed/retry statuses, audit_exports = legacy (last touched ~200 days ago).
DROP TABLE IF EXISTS orders, sync_jobs, audit_exports;

CREATE TABLE orders (
  id serial PRIMARY KEY,
  customer text NOT NULL,
  status text NOT NULL,
  total numeric(10,2) NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);
INSERT INTO orders (customer, status, total, created_at, updated_at)
SELECT 'cust-' || g,
       CASE WHEN g % 10 = 0 THEN 'payment_failed' WHEN g % 7 = 0 THEN 'pending' ELSE 'completed' END,
       (g * 3.5)::numeric(10,2),
       now() - interval '3 days' - (g || ' hours')::interval,
       now() - interval '3 days' - (g || ' minutes')::interval
FROM generate_series(1, 120) g;

CREATE TABLE sync_jobs (
  id serial PRIMARY KEY,
  job_name text NOT NULL,
  last_run_status text NOT NULL,
  last_run_started_at timestamp NOT NULL, -- no time zone on purpose (driver date handling)
  error text
);
INSERT INTO sync_jobs (job_name, last_run_status, last_run_started_at, error)
SELECT 'sync-' || g,
       CASE WHEN g % 4 = 0 THEN 'failed' WHEN g % 5 = 0 THEN 'retrying' ELSE 'succeeded' END,
       (now() AT TIME ZONE 'UTC') - (g * 7 || ' minutes')::interval,
       CASE WHEN g % 4 = 0 THEN 'upstream 502 from inventory API' END
FROM generate_series(1, 30) g;

CREATE TABLE audit_exports (
  id serial PRIMARY KEY,
  state text NOT NULL,
  date date NOT NULL
);
INSERT INTO audit_exports (state, date)
SELECT CASE WHEN g % 3 = 0 THEN 'cancelled' ELSE 'exported' END, (now() - interval '200 days' - (g || ' days')::interval)::date
FROM generate_series(1, 12) g;
