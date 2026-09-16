using System;
using System.IO;
using System.Collections.Generic;
using Microsoft.Data.Sqlite;
using SentinelGuard.Models;

namespace SentinelGuard.Services
{
    public class DatabaseService
    {
        private readonly string _connectionString;
        private readonly HashSet<string> _cachedPaths = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _cachedNames = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _cachedIps = new(StringComparer.OrdinalIgnoreCase);
        private readonly object _lock = new();

        private static void EnsureColumnExists(SqliteConnection conn, string table, string column, string typeDef)
        {
            try
            {
                using var checkCmd = conn.CreateCommand();
                checkCmd.CommandText = $"PRAGMA table_info({table});";
                using var rdr = checkCmd.ExecuteReader();
                bool exists = false;
                while (rdr.Read())
                {
                    string col = rdr.GetString(1);
                    if (string.Equals(col, column, StringComparison.OrdinalIgnoreCase))
                    {
                        exists = true;
                        break;
                    }
                }
                rdr.Close();

                if (!exists)
                {
                    using var alterCmd = conn.CreateCommand();
                    alterCmd.CommandText = $"ALTER TABLE {table} ADD COLUMN {column} {typeDef};";
                    alterCmd.ExecuteNonQuery();
                }
            }
            catch { }
        }

        public DatabaseService(string? dbPath = null)
        {
            if (string.IsNullOrWhiteSpace(dbPath))
            {
                string appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string dir = Path.Combine(appData, "SentinelGuard");
                Directory.CreateDirectory(dir);
                dbPath = Path.Combine(dir, "sentinel.db");
            }
            _connectionString = $"Data Source={dbPath}";
            Initialize();
            ReloadWhitelistCache();
        }

        private void Initialize()
        {
            try
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        event_type TEXT,
                        name TEXT,
                        path TEXT,
                        details TEXT,
                        risk INTEGER,
                        status TEXT,
                        pid INTEGER,
                        parent_name TEXT,
                        parent_pid INTEGER,
                        user_name TEXT,
                        remote_ip TEXT,
                        remote_port INTEGER
                    );

                    CREATE TABLE IF NOT EXISTS quarantine (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        original_path TEXT,
                        quarantine_filename TEXT,
                        sha256 TEXT,
                        quarantined_at TEXT,
                        reason TEXT
                    );

                    CREATE TABLE IF NOT EXISTS whitelist (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        item_type TEXT,
                        value TEXT UNIQUE,
                        added_at TEXT,
                        notes TEXT
                    );
                ";
                cmd.ExecuteNonQuery();

                // Automatic Schema Migration for any pre-existing databases:
                EnsureColumnExists(conn, "events", "risk", "INTEGER DEFAULT 0");
                EnsureColumnExists(conn, "events", "parent_name", "TEXT DEFAULT ''");
                EnsureColumnExists(conn, "events", "parent_pid", "INTEGER DEFAULT 0");
                EnsureColumnExists(conn, "events", "user_name", "TEXT DEFAULT ''");
                EnsureColumnExists(conn, "events", "status", "TEXT DEFAULT 'ACTIVE'");
                EnsureColumnExists(conn, "events", "remote_ip", "TEXT DEFAULT ''");
                EnsureColumnExists(conn, "events", "remote_port", "INTEGER DEFAULT 0");
            }
            catch { }
        }

        private void ReloadWhitelistCache()
        {
            lock (_lock)
            {
                try
                {
                    _cachedPaths.Clear();
                    _cachedNames.Clear();
                    _cachedIps.Clear();

                    using var conn = new SqliteConnection(_connectionString);
                    conn.Open();
                    using var cmd = conn.CreateCommand();
                    cmd.CommandText = "SELECT item_type, value FROM whitelist;";
                    using var rdr = cmd.ExecuteReader();
                    while (rdr.Read())
                    {
                        string type = rdr.GetString(0).ToUpperInvariant();
                        string val = rdr.GetString(1);
                        if (type == "PATH") _cachedPaths.Add(val);
                        else if (type == "NAME") _cachedNames.Add(val);
                        else if (type == "IP") _cachedIps.Add(val);
                    }
                }
                catch { }
            }
        }

        public bool IsWhitelisted(string path = "", string name = "", string ip = "", string parentName = "")
        {
            lock (_lock)
            {
                if (!string.IsNullOrWhiteSpace(path) && _cachedPaths.Contains(path)) return true;
                if (!string.IsNullOrWhiteSpace(name) && _cachedNames.Contains(name)) return true;
                if (!string.IsNullOrWhiteSpace(ip) && _cachedIps.Contains(ip)) return true;
                if (!string.IsNullOrWhiteSpace(parentName))
                {
                    if (_cachedNames.Contains(parentName)) return true;
                    foreach (var cached in _cachedNames)
                    {
                        if (parentName.Contains(cached, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                }
                return false;
            }
        }

        public void AddWhitelist(string type, string value, string notes = "")
        {
            try
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "INSERT OR REPLACE INTO whitelist (item_type, value, added_at, notes) VALUES (@t, @v, @a, @n);";
                cmd.Parameters.AddWithValue("@t", type.ToUpperInvariant());
                cmd.Parameters.AddWithValue("@v", value);
                cmd.Parameters.AddWithValue("@a", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                cmd.Parameters.AddWithValue("@n", notes);
                cmd.ExecuteNonQuery();
                ReloadWhitelistCache();
            }
            catch { }
        }

        private void ReloadWhitelistCacheSafe() => ReloadWhitelistCache();

        private void RemoveWhitelistInternal(int id)
        {
            try
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "DELETE FROM whitelist WHERE id = @id;";
                cmd.Parameters.AddWithValue("@id", id);
                cmd.ExecuteNonQuery();
                ReloadWhitelistCache();
            }
            catch { }
        }

        public void RemoveWhitelist(int id) => RemoveWhitelistInternal(id);
        public void DeleteWhitelist(int id) => RemoveWhitelistInternal(id);

        public List<WhitelistRule> GetWhitelist()
        {
            var list = new List<WhitelistRule>();
            try
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT id, item_type, value, added_at, notes FROM whitelist ORDER BY id DESC;";
                using var rdr = cmd.ExecuteReader();
                int row = 1;
                while (rdr.Read())
                {
                    list.Add(new WhitelistRule
                    {
                        RowNumber = row++,
                        Id = rdr.GetInt32(0),
                        ItemType = rdr.GetString(1),
                        Value = rdr.GetString(2),
                        AddedAt = rdr.GetString(3),
                        Notes = rdr.IsDBNull(4) ? "" : rdr.GetString(4)
                    });
                }
            }
            catch { }
            return list;
        }

        public void AddEvent(SecurityEvent ev)
        {
            try
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    INSERT INTO events (timestamp, event_type, name, path, details, risk, status, pid, parent_name, parent_pid, user_name, remote_ip, remote_port)
                    VALUES (@ts, @et, @n, @p, @d, @r, @s, @pid, @pn, @ppid, @un, @rip, @rp);
                ";
                cmd.Parameters.AddWithValue("@ts", ev.Timestamp);
                cmd.Parameters.AddWithValue("@et", ev.EventType);
                cmd.Parameters.AddWithValue("@n", ev.Name);
                cmd.Parameters.AddWithValue("@p", ev.Path);
                cmd.Parameters.AddWithValue("@d", ev.Details);
                cmd.Parameters.AddWithValue("@r", (int)ev.Risk);
                cmd.Parameters.AddWithValue("@s", ev.Status);
                cmd.Parameters.AddWithValue("@pid", (object?)ev.Pid ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@pn", ev.ParentProcessName);
                cmd.Parameters.AddWithValue("@ppid", (object?)ev.ParentPid ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@un", ev.UserName);
                cmd.Parameters.AddWithValue("@rip", ev.RemoteIp);
                cmd.Parameters.AddWithValue("@rp", (object?)ev.RemotePort ?? DBNull.Value);
                cmd.ExecuteNonQuery();
            }
            catch { }
        }

        public void DeleteEvent(int id)
        {
            try
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "DELETE FROM events WHERE id = @id;";
                cmd.Parameters.AddWithValue("@id", id);
                cmd.ExecuteNonQuery();
            }
            catch { }
        }

        public void ClearEvents()
        {
            try
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "DELETE FROM events;";
                cmd.ExecuteNonQuery();
            }
            catch { }
        }

        public List<SecurityEvent> GetEvents(int limit = 300)
        {
            var list = new List<SecurityEvent>();
            try
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = $"SELECT id, timestamp, event_type, name, path, details, risk, status, pid, parent_name, parent_pid, user_name, remote_ip, remote_port FROM events ORDER BY id DESC LIMIT {limit};";
                using var rdr = cmd.ExecuteReader();
                int row = 1;
                while (rdr.Read())
                {
                    list.Add(new SecurityEvent
                    {
                        RowNumber = row++,
                        Id = rdr.GetInt32(0),
                        Timestamp = rdr.IsDBNull(1) ? "" : rdr.GetString(1),
                        EventType = rdr.IsDBNull(2) ? "" : rdr.GetString(2),
                        Name = rdr.IsDBNull(3) ? "" : rdr.GetString(3),
                        Path = rdr.IsDBNull(4) ? "" : rdr.GetString(4),
                        Details = rdr.IsDBNull(5) ? "" : rdr.GetString(5),
                        Risk = rdr.IsDBNull(6) ? RiskLevel.INFO : (RiskLevel)rdr.GetInt32(6),
                        Status = rdr.IsDBNull(7) ? "ACTIVE" : rdr.GetString(7),
                        Pid = rdr.IsDBNull(8) ? null : rdr.GetInt32(8),
                        ParentProcessName = rdr.IsDBNull(9) ? "" : rdr.GetString(9),
                        ParentPid = rdr.IsDBNull(10) ? null : rdr.GetInt32(10),
                        UserName = rdr.IsDBNull(11) ? "" : rdr.GetString(11),
                        RemoteIp = rdr.IsDBNull(12) ? "" : rdr.GetString(12),
                        RemotePort = rdr.IsDBNull(13) ? null : rdr.GetInt32(13)
                    });
                }
            }
            catch { }
            return list;
        }

        public void AddQuarantine(string origPath, string qFilename, string sha256, string reason)
        {
            try
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "INSERT INTO quarantine (original_path, quarantine_filename, sha256, quarantined_at, reason) VALUES (@o, @q, @s, @t, @r);";
                cmd.Parameters.AddWithValue("@o", origPath);
                cmd.Parameters.AddWithValue("@q", qFilename);
                cmd.Parameters.AddWithValue("@s", sha256);
                cmd.Parameters.AddWithValue("@t", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                cmd.Parameters.AddWithValue("@r", reason);
                cmd.ExecuteNonQuery();
            }
            catch { }
        }

        public List<QuarantineItem> GetQuarantinedFiles()
        {
            var list = new List<QuarantineItem>();
            try
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT id, original_path, quarantine_filename, sha256, quarantined_at, reason FROM quarantine ORDER BY id DESC;";
                using var rdr = cmd.ExecuteReader();
                int row = 1;
                while (rdr.Read())
                {
                    list.Add(new QuarantineItem
                    {
                        RowNumber = row++,
                        Id = rdr.GetInt32(0),
                        OriginalPath = rdr.GetString(1),
                        QuarantineFilename = rdr.GetString(2),
                        Sha256 = rdr.GetString(3),
                        QuarantinedAt = rdr.GetString(4),
                        Reason = rdr.IsDBNull(5) ? "" : rdr.GetString(5)
                    });
                }
            }
            catch { }
            return list;
        }

        public void DeleteQuarantine(int id)
        {
            try
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "DELETE FROM quarantine WHERE id = @id;";
                cmd.Parameters.AddWithValue("@id", id);
                cmd.ExecuteNonQuery();
            }
            catch { }
        }
    }
}
