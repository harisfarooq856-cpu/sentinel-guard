using System;
using System.Collections.Generic;
using Microsoft.Win32;
using SentinelGuard.Models;

namespace SentinelGuard.Services
{
    public class RegistryWatcherService
    {
        public List<InstalledApp> GetAllInstalledSoftware()
        {
            var list = new List<InstalledApp>();
            var hives = new[]
            {
                (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM"),
                (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM (32-bit)"),
                (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU")
            };

            int row = 1;
            foreach (var (hive, subPath, hiveName) in hives)
            {
                try
                {
                    using var key = hive.OpenSubKey(subPath);
                    if (key == null) continue;

                    foreach (var subName in key.GetSubKeyNames())
                    {
                        try
                        {
                            using var appKey = key.OpenSubKey(subName);
                            string dn = appKey?.GetValue("DisplayName")?.ToString() ?? "";
                            if (string.IsNullOrWhiteSpace(dn)) continue;

                            list.Add(new InstalledApp
                            {
                                RowNumber = row++,
                                Name = dn,
                                Version = appKey?.GetValue("DisplayVersion")?.ToString() ?? "",
                                Publisher = appKey?.GetValue("Publisher")?.ToString() ?? "",
                                InstallDate = appKey?.GetValue("InstallDate")?.ToString() ?? "",
                                InstallLocation = appKey?.GetValue("InstallLocation")?.ToString() ?? "",
                                RegistryHive = hiveName
                            });
                        }
                        catch { }
                    }
                }
                catch { }
            }

            return list;
        }

        public List<StartupEntry> GetAllStartupEntries()
        {
            var list = new List<StartupEntry>();
            var runHives = new[]
            {
                (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
                (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run")
            };

            int row = 1;
            foreach (var (hive, subPath, hiveName) in runHives)
            {
                try
                {
                    using var key = hive.OpenSubKey(subPath);
                    if (key == null ) continue;

                    foreach (var valName in key.GetValueNames())
                    {
                        string cmd = key.GetValue(valName)?.ToString() ?? "";
                        var (risk, _) = ThreatAnalyzer.AnalyzeProcess(valName, "", cmd);

                        list.Add(new StartupEntry
                        {
                            RowNumber = row++,
                            Name = valName,
                            Command = cmd,
                            Location = hiveName,
                            EntryType = "Startup Run Key",
                            Risk = risk
                        });
                    }
                }
                catch { }
            }

            return list;
        }
    }
}
