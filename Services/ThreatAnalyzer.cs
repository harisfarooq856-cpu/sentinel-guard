using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Collections.Generic;
using SentinelGuard.Models;

namespace SentinelGuard.Services
{
    public static class ThreatAnalyzer
    {
        private static readonly HashSet<string> SystemBinaries = new(StringComparer.OrdinalIgnoreCase)
        {
            "svchost.exe", "explorer.exe", "lsass.exe", "csrss.exe",
            "services.exe", "smss.exe", "winlogon.exe", "wininit.exe",
            "taskhostw.exe", "ctfmon.exe", "dwm.exe", "spoolsv.exe"
        };

        private static readonly HashSet<string> LegitimateNetworkApps = new(StringComparer.OrdinalIgnoreCase)
        {
            "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "opera.exe",
            "code.exe", "devenv.exe", "MsMpEng.exe", "svchost.exe",
            "SearchHost.exe", "backgroundTaskHost.exe", "RuntimeBroker.exe",
            "language_server.exe", "idle.exe", "git.exe", "curl.exe",
            "SentinelGuard.exe", "python.exe", "node.exe"
        };

        private static readonly HashSet<string> SuspiciousLolBins = new(StringComparer.OrdinalIgnoreCase)
        {
            "powershell.exe", "powershell_ise.exe", "pwsh.exe",
            "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
            "rundll32.exe", "regsvr32.exe", "certutil.exe",
            "bitsadmin.exe", "msbuild.exe"
        };

        private static readonly string[] SuspiciousKeywords = new[]
        {
            "keylogger", "miner", "xmrig", "rat", "backdoor", "trojan",
            "stealer", "exfil", "reverseshell", "metasploit", "mimikatz"
        };

        public static (RiskLevel Risk, string Reasons) AnalyzeProcess(string name, string path, string cmdline = "")
        {
            int score = 0;
            var reasons = new List<string>();

            // 1. Masquerading System Process
            if (SystemBinaries.Contains(name) && !string.IsNullOrWhiteSpace(path))
            {
                string pLower = path.ToLowerInvariant();
                if (!pLower.StartsWith("c:\\windows\\system32") && 
                    !pLower.StartsWith("c:\\windows\\syswow64") && 
                    !pLower.StartsWith("c:\\windows\\explorer.exe"))
                {
                    reasons.Add($"Critical: Process '{name}' is masquerading from {path}");
                    score += 100;
                }
            }

            // 2. Suspicious keywords
            string fullText = $"{name} {path} {cmdline}".ToLowerInvariant();
            foreach (var kw in SuspiciousKeywords)
            {
                if (fullText.Contains(kw))
                {
                    reasons.Add($"Suspicious threat keyword: '{kw}'");
                    score += 80;
                }
            }

            // 3. Suspicious Path (Temp execution)
            if (!string.IsNullOrWhiteSpace(path))
            {
                string pLower = path.ToLowerInvariant();
                if (pLower.Contains("\\temp\\") || pLower.Contains("\\users\\public"))
                {
                    reasons.Add($"Executing from sensitive temp folder: {path}");
                    score += 40;
                }
            }

            // 4. Obfuscated / Encoded Command Flags
            string[] suspFlags = new[] { "-enc ", "encodedcommand", "-w hidden", "downloadstring", "iex(", "certutil -urlcache" };
            foreach (var flag in suspFlags)
            {
                if (fullText.Contains(flag))
                {
                    reasons.Add($"Suspicious execution flag: '{flag}'");
                    score += 60;
                }
            }

            RiskLevel risk = score switch
            {
                >= 80 => RiskLevel.CRITICAL,
                >= 50 => RiskLevel.HIGH,
                >= 25 => RiskLevel.MEDIUM,
                _ => RiskLevel.INFO
            };

            return (risk, string.Join("; ", reasons));
        }

        public static (RiskLevel Risk, string Reasons) AnalyzeNetwork(string procName, string exePath, string remoteIp, int port)
        {
            // 1. Check if this is a standard, legitimate browser or OS service
            if (LegitimateNetworkApps.Contains(procName) && (port == 443 || port == 80 || port == 53))
            {
                return (RiskLevel.INFO, "Verified Windows / Browser HTTPS traffic");
            }

            int score = 0;
            var reasons = new List<string>();

            // 2. If a script engine (LolBin) makes an outbound connection, high risk!
            if (SuspiciousLolBins.Contains(procName))
            {
                reasons.Add($"Script engine '{procName}' establishing network connection");
                score += 65;
            }

            // 3. Known C2 / suspicious ports
            int[] suspPorts = new[] { 4444, 6667, 1337, 8888, 9999, 31337, 5555 };
            if (Array.Exists(suspPorts, p => p == port))
            {
                reasons.Add($"Suspicious C2 / unusual port: {port}");
                score += 60;
            }

            // 4. Process risk factors
            var (pRisk, pReasons) = AnalyzeProcess(procName, exePath);
            if (pRisk >= RiskLevel.HIGH)
            {
                score += 50;
                if (!string.IsNullOrWhiteSpace(pReasons)) reasons.Add(pReasons);
            }

            bool isPrivate = IsPrivateIp(remoteIp);
            if (!isPrivate && score == 0)
            {
                return (RiskLevel.INFO, "External IP connection");
            }

            RiskLevel risk = score switch
            {
                >= 80 => RiskLevel.CRITICAL,
                >= 50 => RiskLevel.HIGH,
                >= 25 => RiskLevel.MEDIUM,
                _ => RiskLevel.INFO
            };

            return (risk, string.Join("; ", reasons));
        }

        private static bool IsPrivateIp(string ipStr)
        {
            if (string.IsNullOrWhiteSpace(ipStr) || ipStr == "0.0.0.0" || ipStr == "127.0.0.1" || ipStr == "::1")
                return true;
            if (IPAddress.TryParse(ipStr, out var ip))
            {
                byte[] bytes = ip.GetAddressBytes();
                if (bytes.Length == 4)
                {
                    if (bytes[0] == 10) return true;
                    if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
                    if (bytes[0] == 192 && bytes[1] == 168) return true;
                }
            }
            return false;
        }

        public static string ComputeSha256(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return "";
                using var sha = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                var hash = sha.ComputeHash(stream);
                return Convert.ToHexString(hash).ToLowerInvariant();
            }
            catch
            {
                return "";
            }
        }
    }
}
