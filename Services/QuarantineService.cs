using System;
using System.IO;
using SentinelGuard.Models;

namespace SentinelGuard.Services
{
    public class QuarantineService
    {
        private readonly string _quarantineDir;
        private readonly DatabaseService _db;

        public QuarantineService(DatabaseService db)
        {
            _db = db;
            string appData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelGuard");
            _quarantineDir = Path.Combine(appData, "quarantine");
            Directory.CreateDirectory(_quarantineDir);
        }

        public bool QuarantineFile(string filePath, string reason = "")
        {
            try
            {
                if (!File.Exists(filePath)) return false;
                string sha = ThreatAnalyzer.ComputeSha256(filePath);
                string qFilename = $"{Guid.NewGuid():N}_{DateTime.Now:yyyyMMdd_HHmmss}.locked";
                string destPath = Path.Combine(_quarantineDir, qFilename);

                File.Move(filePath, destPath);
                File.SetAttributes(destPath, FileAttributes.ReadOnly);

                _db.AddQuarantine(filePath, qFilename, sha, reason);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool RestoreFile(QuarantineItem item)
        {
            try
            {
                string src = Path.Combine(_quarantineDir, item.QuarantineFilename);
                if (!File.Exists(src)) return false;

                string parent = Path.GetDirectoryName(item.OriginalPath) ?? "";
                if (!string.IsNullOrWhiteSpace(parent)) Directory.CreateDirectory(parent);

                File.SetAttributes(src, FileAttributes.Normal);
                File.Move(src, item.OriginalPath, true);
                _db.DeleteQuarantine(item.Id);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool DeleteQuarantined(QuarantineItem item)
        {
            try
            {
                string src = Path.Combine(_quarantineDir, item.QuarantineFilename);
                if (File.Exists(src))
                {
                    File.SetAttributes(src, FileAttributes.Normal);
                    File.Delete(src);
                }
                _db.DeleteQuarantine(item.Id);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
