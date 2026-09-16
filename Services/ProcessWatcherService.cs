using System;
using System.Diagnostics;
using System.Collections.Generic;
using SentinelGuard.Models;

namespace SentinelGuard.Services
{
    public class ProcessWatcherService
    {
        public List<ProcessItem> GetAllProcesses(DatabaseService? db = null)
        {
            var list = new List<ProcessItem>();
            var procs = Process.GetProcesses();
            int row = 1;

            foreach (var p in procs)
            {
                try
                {
                    string path = "";
                    try { path = p.MainModule?.FileName ?? ""; } catch { }

                    double memMB = Math.Round(p.WorkingSet64 / (1024.0 * 1024.0), 1);
                    string pName = p.ProcessName + ".exe";

                    var (parentName, parentPid) = ProcessInfoHelper.GetParentProcess(p.Id);
                    string user = ProcessInfoHelper.GetProcessUser(p.Id);

                    RiskLevel risk = RiskLevel.INFO;
                    if (db != null && db.IsWhitelisted(path, pName, parentName: parentName))
                    {
                        risk = RiskLevel.SAFE;
                    }
                    else
                    {
                        var (analyzedRisk, _) = ThreatAnalyzer.AnalyzeProcess(pName, path);
                        risk = analyzedRisk;
                    }

                    list.Add(new ProcessItem
                    {
                        RowNumber = row++,
                        Pid = p.Id,
                        Name = pName,
                        ParentProcessName = parentName,
                        ParentPid = parentPid,
                        UserName = user,
                        MemoryMB = memMB,
                        ExePath = path,
                        Risk = risk
                    });
                }
                catch { }
            }

            return list;
        }

        public bool TerminateProcess(int pid)
        {
            try
            {
                var p = Process.GetProcessById(pid);
                p.Kill(true);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
