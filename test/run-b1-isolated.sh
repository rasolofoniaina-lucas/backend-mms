#!/usr/bin/env sh
set -eu

test_url="${MMS_TEST_DATABASE_URL:-postgres://mms_test:mms_test_only@db:5432/mms_test}"
test_database="${test_url##*/}"
test_database="${test_database%%\?*}"
case "$test_database" in
  mms_test|*_test) ;;
  *) echo "Refus: DATABASE_URL de test doit viser mms_test ou une base se terminant par _test." >&2; exit 1 ;;
esac

root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
compose="docker compose -f $root/docker-compose.test.yml"

# This project owns only mms_b1_test_postgres_data; the development mms volume is never addressed.
$compose down -v --remove-orphans
$compose up -d --build --wait

export MMS_API_URL="${MMS_API_URL:-http://127.0.0.1:3001}"
export MMS_API_CONTAINER="${MMS_API_CONTAINER:-mms-b1-test-api-1}"
export MMS_TEST_DB_CONTAINER="${MMS_TEST_DB_CONTAINER:-mms-b1-test-db-1}"
node --test test/auth.integration.test.mjs test/staff-tickets.integration.test.mjs test/anonymous-booking.integration.test.mjs test/booking-claim.activation.test.mjs
