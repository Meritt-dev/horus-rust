# Local connector infra

Live services for the connectors that have no shared environment, so the TS and Rust CLIs can be
compared against real systems. Throwaway local credentials only. Every port binds to 127.0.0.1.

## Up / down

```sh
cd infra
./gen-certs.sh                 # throwaway CA + Redis server cert into certs/ (gitignored); once
docker compose up -d --wait
./seed.sh                      # idempotent; needs ../../horus-master (or HORUS_TS_ROOT) for the legacy schema

docker compose stop            # stop, keep containers (Kafka data is lost: it lives in /tmp in the container)
docker compose down            # remove containers; run ./seed.sh again after the next `up`
```

## Services

| Service | Port | Credentials | Used for |
| --- | --- | --- | --- |
| Kafka 3.9.1 (KRaft, single node) | `19092` PLAINTEXT | none | `connect kafka --no-ssl`, `queues --live` lag |
| | `19093` SASL_PLAINTEXT | `horus` / `horus-local-pass` (PLAIN, SCRAM-SHA-256, SCRAM-SHA-512) | SASL paths of the Kafka client |
| Azure SQL Edge 1.0.7 (SQL Server) | `11433` | `sa` / `Horus-local-Pass1`; read-only `horus_ro` / `Horus-local-Pass1`; database `shop` | `connect sqlserver`, `state` |
| Postgres 16.10 | `15432` | `horus` / `horus-local-pass`; databases `shop`, `horus_legacy` | `connect postgres`, `state`; `db import --from …/horus_legacy` |
| Redis 7.4.5, TLS only | `16380` | password `horus-local-pass`; CA `certs/ca.crt` | `connect redis` over `rediss://`, BullMQ in `queues --live` |

Connection strings:

```
kafka brokers   127.0.0.1:19092  (plain)    127.0.0.1:19093  (SASL)
sqlserver       Server=127.0.0.1,11433;User Id=horus_ro;Password=Horus-local-Pass1;Encrypt=true;TrustServerCertificate=true
postgres        postgres://horus:horus-local-pass@127.0.0.1:15432/shop
legacy horus db postgres://horus:horus-local-pass@127.0.0.1:15432/horus_legacy
redis           rediss://:horus-local-pass@localhost:16380
```

The Redis cert is signed by the throwaway CA, so clients must trust `certs/ca.crt`:
`NODE_EXTRA_CA_CERTS=infra/certs/ca.crt` for the TS CLI, `SSL_CERT_FILE=infra/certs/ca.crt` for the
Rust CLI (rustls-native-certs).

## Seed data

- **Kafka**: topics `orders.created` (3 partitions, 300 msgs), `payments.settled` (2, 80),
  `inventory.sync` (3, 150). Groups: `order-worker` lags on partitions 0-1 and never committed
  partition 2; `payment-worker` is caught up; `inventory-sync` committed at offset 0 (full lag).
- **SQL Server / Postgres `shop`**: `orders` (stale: last update 3 days ago, `payment_failed` and
  `pending` rows), `sync_jobs` (active, `failed` / `retrying` runs), `audit_exports` (legacy: ~200 days old).
- **Postgres `horus_legacy`**: the legacy Horus schema (all `packages/db/drizzle` migrations) with two
  investigations and rows in every imported table.
- **Redis**: db 1 holds BullMQ queues under prefix `bull` (`emails`: waiting, active, failed with two
  reasons, completed; `webhooks`: paused, delayed, one stale failure; `reports`: idle). db 0 holds cache keys.
