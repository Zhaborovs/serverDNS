-- Combain-Mesh SQLite Schema (LWW + Tombstones)

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
    node_id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL CHECK(role IN ('ru_relay', 'exit')),
    public_ip TEXT NOT NULL DEFAULT '',
    public_ipv6 TEXT NOT NULL DEFAULT '',
    country_code TEXT NOT NULL DEFAULT '',
    mesh_ip TEXT NOT NULL DEFAULT '',
    base_domain TEXT NOT NULL DEFAULT '',
    dns_domain TEXT NOT NULL DEFAULT '',
    xhttp_path TEXT NOT NULL DEFAULT '',
    ws_path TEXT NOT NULL DEFAULT '',
    vless_pub_key TEXT NOT NULL DEFAULT '',
    awg_port INTEGER NOT NULL DEFAULT 0,
    wg_pubkey TEXT NOT NULL DEFAULT '',
    wg_port INTEGER NOT NULL DEFAULT 51829,
    status TEXT NOT NULL DEFAULT 'online',
    last_seen INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT 0,
    deleted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    uuid TEXT NOT NULL,
    sub_token TEXT UNIQUE NOT NULL,
    max_devices INTEGER NOT NULL DEFAULT 3,
    expires_at INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    note TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL DEFAULT 0,
    deleted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS user_devices (
    user_id TEXT NOT NULL,
    hwid TEXT NOT NULL,
    last_ip TEXT NOT NULL DEFAULT '',
    last_seen INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT 0,
    deleted INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(user_id, hwid)
);

CREATE INDEX IF NOT EXISTS idx_nodes_updated_at ON nodes(updated_at);
CREATE INDEX IF NOT EXISTS idx_users_updated_at ON users(updated_at);
CREATE INDEX IF NOT EXISTS idx_user_devices_updated_at ON user_devices(updated_at);
CREATE INDEX IF NOT EXISTS idx_user_devices_user_active ON user_devices(user_id, deleted);
