#!/usr/bin/env sh
# Prepares PostgreSQL for the masterpod server. Safe to re-run.
#
# For the env file given (default: .env in the project root) it
#   1. creates the application role if it is missing and syncs its password,
#   2. creates the database if it is missing,
#   3. applies db/schema.sql (functions, tables, triggers, comments).
#
# Step 3 only adds what is missing; it never changes a table that already
# exists. After editing db/schema.sql, rebuild the local database with
# `npm run db:reset`.
#
# Steps 1 and 2 connect as a superuser over the local unix socket, so run the
# script as an OS user that PostgreSQL trusts. Step 3 connects with the env
# file's PG* settings, as the app role, so the app role owns its tables.
#
#   local (Homebrew):   npm run db:setup
#                       sh scripts/setup-db.sh .env.other   # another env file
set -eu

cd "$(dirname "$0")/.."
. scripts/find-psql.sh

env_file="${1:-.env}"
if [ ! -f "$env_file" ]; then
  echo "$env_file: no such file. Copy .env.example to .env and fill it in first." >&2
  exit 1
fi
case $env_file in /*) ;; *) env_file="./$env_file" ;; esac

set -a
. "$env_file"
set +a

: "${PGDATABASE:?PGDATABASE is not set in $env_file}"
: "${PGUSER:?PGUSER is not set in $env_file}"
: "${PGPASSWORD:?PGPASSWORD is not set in $env_file}"

# Role and database: as the current OS user over the local socket, so the
# app's PG* variables are unset for this one call. %I and %L in format()
# quote identifiers and literals safely.
env -u PGHOST -u PGPORT -u PGUSER -u PGPASSWORD -u PGDATABASE \
  "$PSQL" -X -q -v ON_ERROR_STOP=1 -d postgres \
  -v db_name="$PGDATABASE" -v db_user="$PGUSER" -v db_password="$PGPASSWORD" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'db_user', :'db_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'db_user')\gexec

SELECT format('ALTER ROLE %I WITH PASSWORD %L', :'db_user', :'db_password')\gexec

SELECT format('CREATE DATABASE %I OWNER %I', :'db_name', :'db_user')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'db_name')\gexec
SQL

# Schema: as the app role, with the file's PG* settings.
"$PSQL" -X -q -v ON_ERROR_STOP=1 -1 -f db/schema.sql

echo "$env_file: role '$PGUSER' and database '$PGDATABASE' are ready (schema applied)."
