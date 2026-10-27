#!/usr/bin/env sh
# Drops the database named in the given env file (default: .env in the
# project root) and runs setup-db.sh again, so it comes back empty and built
# from the current db/schema.sql.
#
# Everything in that database is lost; that is the point. It is for local
# development after a schema change. WITH (FORCE) disconnects a server that
# is still running, so stop it first if you want a clean log.
#
#   npm run db:reset
#   sh scripts/reset-db.sh .env.other   # another env file
set -eu

cd "$(dirname "$0")/.."
. scripts/find-psql.sh

if [ "${NODE_ENV:-}" = production ]; then
  echo "Refusing to drop a database with NODE_ENV=production." >&2
  exit 1
fi

env_file="${1:-.env}"
if [ ! -f "$env_file" ]; then
  echo "$env_file: no such file; nothing to reset." >&2
  exit 1
fi
case $env_file in /*) ;; *) env_file="./$env_file" ;; esac

# A subshell, so the file's variables never leak into setup-db.sh below.
(
  set -a
  . "$env_file"
  set +a

  : "${PGDATABASE:?PGDATABASE is not set in $env_file}"

  env -u PGHOST -u PGPORT -u PGUSER -u PGPASSWORD -u PGDATABASE \
    "$PSQL" -X -q -v ON_ERROR_STOP=1 -d postgres -v db_name="$PGDATABASE" <<'SQL'
SELECT format('DROP DATABASE IF EXISTS %I WITH (FORCE)', :'db_name')\gexec
SQL

  echo "$env_file: dropped database '$PGDATABASE'."
)

exec sh scripts/setup-db.sh "$@"
