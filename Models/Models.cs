using System;

namespace SentinelGuard.Models
{
    public enum RiskLevel
    {
        SAFE = 0,
        INFO = 1,
        LOW = 2,
        MEDIUM = 3,
        HIGH = 4,
        CRITICAL = 5
    }

    public class SecurityEvent
    {
        public bool IsSelected { get; set; }
        public int RowNumber { get; set; }
        public int Id { get; set; }
        public string Timestamp { get; set; } = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        public string EventType { get; set; } = "";
        public string Name { get; set; } = "";
        public string Path { get; set; } = "";
        public string Details { get; set; } = "";
        public RiskLevel Risk { get; set; } = RiskLevel.INFO;
        public string Status { get; set; } = "ACTIVE";
        public int? Pid { get; set; }
        public string ParentProcessName { get; set; } = "";
        public int? ParentPid { get; set; }
        public string UserName { get; set; } = "";
        public string Hash { get; set; } = "";
        public string SignatureStatus { get; set; } = "UNKNOWN";
        public string RemoteIp { get; set; } = "";
        public int? RemotePort { get; set; }

        public string DisplayUser => !string.IsNullOrWhiteSpace(UserName) ? UserName : Environment.UserName;

        public string SpawnedBy
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(ParentProcessName))
                {
                    if (ParentProcessName.Contains("(") || ParentProcessName.Contains("➔"))
                        return ParentProcessName;
                    return ParentPid != null && ParentPid > 0 ? $"{ParentProcessName} ({ParentPid})" : ParentProcessName;
                }
                return "System";
            }
        }

        public string RiskBadgeBg => Risk switch
        {
            RiskLevel.SAFE => "#D1FAE5",
            RiskLevel.CRITICAL => "#FEE2E2",
            RiskLevel.HIGH => "#FFEDD6",
            RiskLevel.MEDIUM => "#FEF3C7",
            RiskLevel.LOW => "#E0F2FE",
            _ => "#F1F5F9"
        };

        public string RiskBadgeFg => Risk switch
        {
            RiskLevel.SAFE => "#065F46",
            RiskLevel.CRITICAL => "#991B1B",
            RiskLevel.HIGH => "#9A3412",
            RiskLevel.MEDIUM => "#92400E",
            RiskLevel.LOW => "#075985",
            _ => "#475569"
        };
    }

    public class NetworkSocketInfo
    {
        public bool IsSelected { get; set; }
        public int RowNumber { get; set; }
        public string ProcessName { get; set; } = "";
        public int Pid { get; set; }
        public string ParentProcessName { get; set; } = "";
        public int? ParentPid { get; set; }
        public string UserName { get; set; } = "";
        public string LocalEndpoint { get; set; } = "";
        public string RemoteEndpoint { get; set; } = "";
        public string RemoteIp { get; set; } = "";
        public int RemotePort { get; set; }
        public string Protocol { get; set; } = "TCP";
        public string State { get; set; } = "ESTABLISHED";
        public RiskLevel Risk { get; set; } = RiskLevel.INFO;
        public string Path { get; set; } = "";

        public string DisplayUser => !string.IsNullOrWhiteSpace(UserName) ? UserName : Environment.UserName;

        public string SpawnedBy
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(ParentProcessName))
                {
                    if (ParentProcessName.Contains("(") || ParentProcessName.Contains("➔"))
                        return ParentProcessName;
                    return ParentPid != null && ParentPid > 0 ? $"{ParentProcessName} ({ParentPid})" : ParentProcessName;
                }
                return "System";
            }
        }

        public string RiskBadgeBg => Risk switch
        {
            RiskLevel.SAFE => "#D1FAE5",
            RiskLevel.CRITICAL => "#FEE2E2",
            RiskLevel.HIGH => "#FFEDD6",
            RiskLevel.MEDIUM => "#FEF3C7",
            RiskLevel.LOW => "#E0F2FE",
            _ => "#F1F5F9"
        };

        public string RiskBadgeFg => Risk switch
        {
            RiskLevel.SAFE => "#065F46",
            RiskLevel.CRITICAL => "#991B1B",
            RiskLevel.HIGH => "#9A3412",
            RiskLevel.MEDIUM => "#92400E",
            RiskLevel.LOW => "#075985",
            _ => "#475569"
        };
    }

    public class ProcessItem
    {
        public bool IsSelected { get; set; }
        public int RowNumber { get; set; }
        public int Pid { get; set; }
        public string Name { get; set; } = "";
        public string ParentProcessName { get; set; } = "";
        public int? ParentPid { get; set; }
        public string UserName { get; set; } = "";
        public double MemoryMB { get; set; }
        public string ExePath { get; set; } = "";
        public string CommandLine { get; set; } = "";
        public RiskLevel Risk { get; set; } = RiskLevel.INFO;

        public string DisplayUser => !string.IsNullOrWhiteSpace(UserName) ? UserName : Environment.UserName;

        public string SpawnedBy
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(ParentProcessName))
                {
                    if (ParentProcessName.Contains("(") || ParentProcessName.Contains("➔"))
                        return ParentProcessName;
                    return ParentPid != null && ParentPid > 0 ? $"{ParentProcessName} ({ParentPid})" : ParentProcessName;
                }
                return "System";
            }
        }

        public string RiskBadgeBg => Risk switch
        {
            RiskLevel.SAFE => "#D1FAE5",
            RiskLevel.CRITICAL => "#FEE2E2",
            RiskLevel.HIGH => "#FFEDD6",
            RiskLevel.MEDIUM => "#FEF3C7",
            RiskLevel.LOW => "#E0F2FE",
            _ => "#F1F5F9"
        };

        public string RiskBadgeFg => Risk switch
        {
            RiskLevel.SAFE => "#065F46",
            RiskLevel.CRITICAL => "#991B1B",
            RiskLevel.HIGH => "#9A3412",
            RiskLevel.MEDIUM => "#92400E",
            RiskLevel.LOW => "#075985",
            _ => "#475569"
        };
    }

    public class InstalledApp
    {
        public int RowNumber { get; set; }
        public string Name { get; set; } = "";
        public string Version { get; set; } = "";
        public string Publisher { get; set; } = "";
        public string InstallDate { get; set; } = "";
        public string InstallLocation { get; set; } = "";
        public string RegistryHive { get; set; } = "";
    }

    public class StartupEntry
    {
        public int RowNumber { get; set; }
        public string Name { get; set; } = "";
        public string Command { get; set; } = "";
        public string Location { get; set; } = "";
        public string EntryType { get; set; } = "";
        public RiskLevel Risk { get; set; } = RiskLevel.INFO;

        public string RiskBadgeBg => Risk switch
        {
            RiskLevel.SAFE => "#D1FAE5",
            RiskLevel.CRITICAL => "#FEE2E2",
            RiskLevel.HIGH => "#FFEDD6",
            RiskLevel.MEDIUM => "#FEF3C7",
            RiskLevel.LOW => "#E0F2FE",
            _ => "#F1F5F9"
        };

        public string RiskBadgeFg => Risk switch
        {
            RiskLevel.SAFE => "#065F46",
            RiskLevel.CRITICAL => "#991B1B",
            RiskLevel.HIGH => "#9A3412",
            RiskLevel.MEDIUM => "#92400E",
            RiskLevel.LOW => "#075985",
            _ => "#475569"
        };
    }

    public class QuarantineItem
    {
        public int RowNumber { get; set; }
        public int Id { get; set; }
        public string OriginalPath { get; set; } = "";
        public string QuarantineFilename { get; set; } = "";
        public string Sha256 { get; set; } = "";
        public string QuarantinedAt { get; set; } = "";
        public string Reason { get; set; } = "";
    }

    public class WhitelistRule
    {
        public int RowNumber { get; set; }
        public int Id { get; set; }
        public string ItemType { get; set; } = "";
        public string Value { get; set; } = "";
        public string AddedAt { get; set; } = "";
        public string Notes { get; set; } = "";
    }
}
