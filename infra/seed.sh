#!/bin/sh
# Seeds the running horus-infra services. Idempotent: re-running rebuilds the seed data.
# HORUS_TS_ROOT points at the TS monorepo whose packages/db/drizzle migrations define the legacy schema.
set -eu
cd "$(dirname "$0")"
HORUS_TS_ROOT=${HORUS_TS_ROOT:-../../horus-master}
dc() { docker compose "$@"; }

echo "== postgres: shop (app tables) =="
export PGOPTIONS='-c client_min_messages=warning'
dc exec -T -e PGOPTIONS postgres psql -q -v ON_ERROR_STOP=1 -U horus -d shop -f /seed/postgres-shop.sql

echo "== postgres: horus_legacy (legacy Horus schema) =="
dc exec -T -e PGOPTIONS postgres psql -q -U horus -d shop -c 'DROP DATABASE IF EXISTS horus_legacy' -c 'CREATE DATABASE horus_legacy'
# drizzle's `--> statement-breakpoint` markers are SQL comments, so the files apply as-is.
cat "$HORUS_TS_ROOT"/packages/db/drizzle/0*.sql | dc exec -T -e PGOPTIONS postgres psql -q -v ON_ERROR_STOP=1 -U horus -d horus_legacy
dc exec -T -e PGOPTIONS postgres psql -q -v ON_ERROR_STOP=1 -U horus -d horus_legacy -f /seed/legacy-rows.sql

echo "== sqlserver: shop =="
i=0
until dc run --rm -T sqlcmd /opt/mssql-tools/bin/sqlcmd -S sqlserver -U sa -P 'Horus-local-Pass1' -Q 'SELECT 1' >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 30 ] || { echo "sqlserver not ready"; exit 1; }; sleep 2
done
dc run --rm -T sqlcmd /opt/mssql-tools/bin/sqlcmd -b -S sqlserver -U sa -P 'Horus-local-Pass1' -i /seed/sqlserver.sql >/dev/null

echo "== kafka: topics, messages, consumer groups, SCRAM user =="
K="dc exec -T kafka /opt/kafka/bin"
BS="--bootstrap-server 127.0.0.1:19092"
for g in order-worker payment-worker inventory-sync; do $K/kafka-consumer-groups.sh $BS --delete --group $g >/dev/null 2>&1 || true; done
for name in orders.created payments.settled inventory.sync; do
  $K/kafka-topics.sh $BS --delete --topic "$name" >/dev/null 2>&1 || true
done
sleep 2
for t in orders.created:3:300 payments.settled:2:80 inventory.sync:3:150; do
  name=$(echo "$t" | cut -d: -f1); parts=$(echo "$t" | cut -d: -f2); n=$(echo "$t" | cut -d: -f3)
  $K/kafka-topics.sh $BS --create --topic "$name" --partitions "$parts" --replication-factor 1 >/dev/null
  # Keyed messages spread over partitions.
  seq 1 "$n" | awk -v t="$name" '{print "k" $1 "|{\"topic\":\"" t "\",\"n\":" $1 "}"}' |
    $K/kafka-console-producer.sh $BS --topic "$name" --property parse.key=true --property 'key.separator=|' >/dev/null
done
# order-worker: lagging on partitions 0-1, never committed on partition 2.
$K/kafka-consumer-groups.sh $BS --group order-worker --topic orders.created:0,1 --reset-offsets --to-offset 20 --execute >/dev/null
# payment-worker: fully caught up (no lag).
$K/kafka-consumer-groups.sh $BS --group payment-worker --topic payments.settled --reset-offsets --to-latest --execute >/dev/null
# inventory-sync: committed at the start of every partition (lag = everything).
$K/kafka-consumer-groups.sh $BS --group inventory-sync --topic inventory.sync --reset-offsets --to-earliest --execute >/dev/null
# One mechanism per request (KRaft rejects altering one user twice in a single request).
for m in SCRAM-SHA-256 SCRAM-SHA-512; do
  $K/kafka-configs.sh $BS --alter --entity-type users --entity-name horus --add-config "$m=[password=horus-local-pass]" >/dev/null
done

echo "== redis-tls: BullMQ keys (db 1, prefix bull) + cache keys (db 0) =="
now=$(($(date +%s) * 1000))
{
  echo "FLUSHALL"
  echo "SELECT 0"
  for i in 1 2 3 4 5; do echo "SET cache:product:$i '{\"id\":$i}' EX 3600"; done
  echo "HSET session:abc user 42 status active"
  echo "SELECT 1"
  # emails: 4 waiting (oldest 2h old), 1 active, 6 failed (two reasons), 10 completed.
  echo "HSET bull:emails:meta opts.maxLenEvents 10000 version bullmq:5.12.0"
  for i in 1 2 3 4; do
    echo "HSET bull:emails:$i name send-receipt data '{\"to\":\"u$i@example.com\"}' timestamp $((now - (5 - i) * 1800000)) attemptsMade 0"
    echo "LPUSH bull:emails:wait $i"
  done
  echo "HSET bull:emails:5 name send-receipt data '{}' timestamp $((now - 60000)) processedOn $((now - 30000))"
  echo "LPUSH bull:emails:active 5"
  for i in 6 7 8 9 10 11; do
    if [ "$i" -le 9 ]; then r="SMTP 421 Too many connections\n    at SMTPConnection._onError"; else r="Invalid recipient address"; fi
    # printf keeps the literal \n for redis-cli to unescape (macOS sh's echo would expand it).
    printf '%s\n' "HSET bull:emails:$i name send-receipt data '{}' timestamp $((now - 7200000)) attemptsMade 3 failedReason \"$r\" finishedOn $((now - (12 - i) * 600000))"
    echo "ZADD bull:emails:failed $((now - (12 - i) * 600000)) $i"
  done
  for i in $(seq 12 21); do echo "ZADD bull:emails:completed $((now - i * 1000)) $i"; done
  # webhooks: paused with 3 jobs, 2 delayed, 1 failed 3 days ago (stale failure).
  echo "HSET bull:webhooks:meta opts.maxLenEvents 10000 paused 1 version bullmq:5.12.0"
  for i in 1 2 3; do echo "HSET bull:webhooks:$i name deliver data '{}' timestamp $((now - 600000))"; echo "LPUSH bull:webhooks:paused $i"; done
  echo "ZADD bull:webhooks:delayed $((now + 60000)) 4 $((now + 120000)) 5"
  echo "HSET bull:webhooks:6 name deliver data '{}' timestamp $((now - 259300000)) failedReason 'ECONNREFUSED 10.0.0.12:443' finishedOn $((now - 259200000))"
  echo "ZADD bull:webhooks:failed $((now - 259200000)) 6"
  # reports: idle queue (meta only).
  echo "HSET bull:reports:meta opts.maxLenEvents 10000 version bullmq:5.12.0"
} | dc exec -T redis-tls redis-cli --tls --cacert /certs/ca.crt -p 6380 -a horus-local-pass --no-auth-warning >/dev/null

echo "seed complete"
