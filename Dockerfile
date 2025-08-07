FROM debian:bookworm 

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git build-essential cmake pkg-config libssl-dev zlib1g-dev libaio-dev libjemalloc-dev libpcre3-dev libreadline-dev libcurl4-openssl-dev liblz4-dev libzstd-dev libicu-dev libevent-dev default-libmysqlclient-dev libmariadb-dev-compat libpq-dev bison flex autoconf automake libtool libtool-bin m4 pkg-config gettext libgnutls28-dev libgcrypt20-dev python3 python-is-python3 uuid-dev curl mariadb-client mariadb-server supervisor pip python3.11-venv vim && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY <<'SQLLOADAPP' /root/app.py
import os
import sys
import time
import signal
import random
import threading
from contextlib import closing

import pymysql
from faker import Faker

# --- Config via env vars ---
MYSQL_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", "6033"))
MYSQL_USER = os.getenv("MYSQL_USER", "app")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "app")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "people_db")
TARGET_ROWS = int(os.getenv("TARGET_ROWS", "10000"))

def connect(db=None):
    return pymysql.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=db,
        autocommit=True,
        cursorclass=pymysql.cursors.Cursor,
        charset="utf8mb4",
    )

def row_count(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM people;")
        return cur.fetchone()[0]

def generate_name(faker):
    return faker.name()

def seed_people(conn, target_rows=TARGET_ROWS, faker=None):
    existing = row_count(conn)
    remaining = max(0, target_rows - existing)
    if remaining == 0:
        print(f"[seed] Already have {existing} rows. Skipping seed insert.")
        return

    print(f"[seed] Inserting {remaining} rows, one row at a time...")
    with conn.cursor() as cur:
        for i in range(remaining):
            name = generate_name(faker)
            cur.execute("INSERT INTO people (name) VALUES (%s);", (name,))
            if (i + 1) % 100 == 0 or i + 1 == remaining:
                print(f"[seed] Inserted {i + 1}/{remaining}")
    print("[seed] Done.")

def random_like_pattern(faker):
    sample = faker.name()
    parts = [p for p in sample.replace(".", "").split() if p]
    token = random.choice(parts) if parts else sample
    token = token.strip()
    if len(token) > 4:
        start = random.randint(0, max(0, len(token) - 3))
        token = token[start:start + random.randint(2, min(4, len(token) - start))]

    mode = random.choice(["prefix", "suffix", "contains"])
    if mode == "prefix":
        return f"{token}%"
    elif mode == "suffix":
        return f"%{token}"
    else:
        return f"%{token}%"

def insert_worker(stop_event: threading.Event):
    faker = Faker()
    try:
        with closing(connect(MYSQL_DATABASE)) as conn:
            # Seed to TARGET_ROWS first (if needed)
            seed_people(conn, TARGET_ROWS, faker=faker)

            # Then keep inserting one per second until stopped
            print("[insert] Now inserting 1 row/second until stopped. Press Ctrl-C to stop.")
            i = 0
            with conn.cursor() as cur:
                while not stop_event.is_set():
                    name = generate_name(faker)
                    cur.execute("INSERT INTO people (name) VALUES (%s);", (name,))
                    i += 1
                    if i % 10 == 0:
                        # Light progress signal without being too chatty
                        total = row_count(conn)
                        print(f"[insert] Inserted {i} rows in background (total now {total}).")
                    # Sleep last to keep interval ~1s even if insert is fast
                    for _ in range(10):
                        if stop_event.is_set():
                            break
                        time.sleep(0.01)
    except Exception as e:
        print(f"[insert] Error: {e}", file=sys.stderr)

def select_worker(stop_event: threading.Event):
    faker = Faker()
    try:
        with closing(connect(MYSQL_DATABASE)) as conn:
            print("[query] Running 1 query/second. Press Ctrl-C to stop.")
            with conn.cursor() as cur:
                while not stop_event.is_set():
                    pattern = random_like_pattern(faker)
                    cur.execute("SELECT COUNT(*) FROM people WHERE name LIKE %s;", (pattern,))
                    count = cur.fetchone()[0]
                    print(f"[query] LIKE '{pattern}' -> {count} matches")
                    for _ in range(10):
                        if stop_event.is_set():
                            break
                        time.sleep(0.01)
    except Exception as e:
        print(f"[query] Error: {e}", file=sys.stderr)

def main():
    # Make Ctrl-C behave nicely with threads
    signal.signal(signal.SIGINT, signal.default_int_handler)

    stop_event = threading.Event()
    threads = []

    t_insert = threading.Thread(target=insert_worker, args=(stop_event,), name="insert-worker", daemon=True)
    t_select = threading.Thread(target=select_worker, args=(stop_event,), name="select-worker", daemon=True)
    threads.extend([t_insert, t_select])

    for t in threads:
        t.start()

    try:
        # Block main thread until interrupted
        while any(t.is_alive() for t in threads):
            time.sleep(0.2)
    except KeyboardInterrupt:
        print("\n[main] Stopping…")
        stop_event.set()
        for t in threads:
            t.join(timeout=5.0)
        print("[main] Stopped.")

if __name__ == "__main__":
    main()
SQLLOADAPP

COPY <<'SQLLOADAPPREQUIREMENTS' /root/requirements.txt
pymysql==1.1.1
Faker==26.0.0
SQLLOADAPPREQUIREMENTS

COPY <<'SQLLOADAPPSCRIPT' /root/runapp.sh
sleep 10
python3 -m venv /venv
. /venv/bin/activate
pip install --no-cache-dir -r /root/requirements.txt
python /root/app.py
SQLLOADAPPSCRIPT

RUN chmod +x /root/runapp.sh

COPY <<'SUPERVISOR' /etc/supervisor/supervisord.conf
[supervisord]
nodaemon=true
logfile=/dev/null

[include]
files = /etc/supervisor/conf.d/*.conf
SUPERVISOR

COPY <<'PROXYSQL' /etc/supervisor/conf.d/proxysql.conf
[program:proxysql]
command=/bin/bash -lc 'exec /src/src/proxysql -f -c /root/proxysql.cnf'
priority=15
autostart=true
autorestart=false
stopasgroup=true
killasgroup=true
redirect_stderr=false
stdout_logfile=/dev/fd/1
stdout_logfile_maxbytes=0
stderr_logfile=/dev/fd/2
stderr_logfile_maxbytes=0
PROXYSQL

COPY <<'MYSQL' /etc/supervisor/conf.d/mysqld.conf
[program:mysqld]
priority=10
command=/usr/sbin/mysqld --user=mysql --datadir=/var/lib/mysql --socket=/run/mysqld/mysqld.sock --bind-address=0.0.0.0 --skip-networking=0
autostart=true
autorestart=false
MYSQL

COPY <<'MYSQLUSERSCRIPT' /root/create_users.sh
sleep 10
/usr/bin/mysql -u root -e "CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED BY 'app'; GRANT ALL PRIVILEGES ON *.* TO 'app'@'%' WITH GRANT OPTION; FLUSH PRIVILEGES;"
/usr/bin/mysql -u root -e "CREATE USER 'proxysql_mon'@'%' IDENTIFIED BY 'monpass'; GRANT USAGE, PROCESS, REPLICATION CLIENT ON *.* TO 'proxysql_mon'@'%';"
/usr/bin/mysql -u root -e "CREATE DATABASE IF NOT EXISTS people_db; USE people_db; CREATE TABLE IF NOT EXISTS people (id   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, name VARCHAR(255)     NOT NULL, PRIMARY KEY (id)) ENGINE=InnoDB;"
MYSQLUSERSCRIPT

RUN chmod +x /root/create_users.sh

COPY <<'MYSQLUSER' /etc/supervisor/conf.d/mysqlduser.conf
[program:mysqlduser]
priority=20
command=/usr/bin/sh -c /root/create_users.sh
autostart=true
autorestart=false
MYSQLUSER

COPY <<'RUNAPP' /etc/supervisor/conf.d/runapp.conf
[program:runapp]
priority=20
command=/usr/bin/sh -c /root/runapp.sh
autostart=true
autorestart=false
RUNAPP

COPY <<'PROXYSQLCONFIG' /root/proxysql.cnf
datadir="/tmp/proxysql"

admin_variables=
{
    admin_credentials="admin:admin"
    mysql_ifaces="0.0.0.0:6032"
    refresh_interval=2000
    web_enabled=true
    web_port=6080

    restapi_enabled=true
    restapi_port=6070
    prometheus_memory_metrics_interval=61
}

mysql_variables=
{
    # Core MySQL proxy settings
    threads=4
    max_connections=2048
    default_query_delay=0
    default_query_timeout=36000000
    have_compress=true
    poll_timeout=2000
    interfaces="0.0.0.0:6033"
    default_schema="information_schema"
    stacksize=1048576
    server_version="8.0.25-ProxySQL"
    connect_timeout_server=3000
    monitor_username="proxysql_mon"
    monitor_password="monpass"
    monitor_history=600000
    monitor_connect_interval=60000
    monitor_ping_interval=10000
    monitor_read_only_interval=1500
    monitor_read_only_timeout=500
    ping_interval_server_msec=120000
    ping_timeout_server=500
    commands_stats=true
    sessions_sort=true
    connect_retries_on_failure=10
    
    # T-Digest Latency Tracking Configuration
	# Core Settings
	command_latency_tracking_enabled=true
	command_latency_tracking_quantiles="0.5,0.9,0.95,0.99"
	
	# Performance Tuning
	command_latency_tracking_compression=10000    # 100.0 compression factor
	command_latency_tracking_max_centroids=2048   # Memory limit per command type  
	command_latency_tracking_max_unmerged=100     # Buffer size before compression

    # disable ssl
    ssl_p2s_cert=""
    ssl_p2s_key=""
    ssl_p2s_ca=""
}

postgres_variables=
{
	interfaces="0.0.0.0:5432"
	threads=4
	max_connections=2048
	poll_timeout=2000
	command_latency_tracking_enabled=true
	command_latency_tracking_quantiles="0.5,0.9,0.95,0.99"
	command_latency_tracking_compression=10000    # 100.0 compression factor
	command_latency_tracking_max_centroids=2048   # Memory limit per command type
	command_latency_tracking_max_unmerged=100     # Buffer size before compression
}

# Empty arrays to start with clean slate - populate via admin interface
mysql_servers =
(
  {
    address = "127.0.0.1"
    port = 3306
    hostgroup = 10
  }
)
mysql_users =
(
  {
    username = "app"
    password = "app"
    default_hostgroup = 10
    active = 1
  }
)
mysql_query_rules=()
mysql_replication_hostgroups=()
mysql_galera_hostgroups=()
mysql_group_replication_hostgroups=()
mysql_aws_aurora_hostgroups=()

# No schedulers or REST API endpoints by default
scheduler=()
restapi=()

# No clustered ProxySQL servers initially
proxysql_servers=()
PROXYSQLCONFIG

COPY . .

RUN bash -o pipefail -c '\
  set -eux; \
  make clean_deps || true; \
  MAKEFLAGS= V=1 make -Otarget -j1 build_deps_default 2>&1 | tee /root/build_deps.log \
'

RUN bash -o pipefail -c '\
  set -eux; \
  export CXXFLAGS="${CXXFLAGS:-} -Wno-array-bounds"; \
  MAKEFLAGS= V=1 make -Otarget -j1 build_lib_default 2>&1 | tee /root/build_lib.log \
'

RUN bash -o pipefail -c '\
  set -eux; \
  export CXXFLAGS="${CXXFLAGS:-} -Wno-array-bounds"; \
  make -j"$(nproc)"; \
'

RUN mkdir -p /tmp/proxysql
RUN install -d -o mysql -g mysql /var/lib/mysql /run/mysqld

CMD ["supervisord", "-c", "/etc/supervisor/supervisord.conf"]
