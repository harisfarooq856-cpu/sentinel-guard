using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace SentinelGuard.Services
{
    public static class ProcessInfoHelper
    {
        private const uint TH32CS_SNAPPROCESS = 0x00000002;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private static readonly Dictionary<int, (string Name, int PPid)> _processTree = new();
        private static DateTime _lastTreeRefresh = DateTime.MinValue;
        private static readonly object _treeLock = new();

        public static void RefreshProcessTree()
        {
            lock (_treeLock)
            {
                var snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1))
                    return;

                try
                {
                    var pe = new PROCESSENTRY32();
                    pe.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));

                    var tempTree = new Dictionary<int, (string Name, int PPid)>();

                    if (Process32First(snapshot, ref pe))
                    {
                        do
                        {
                            int pid = (int)pe.th32ProcessID;
                            int ppid = (int)pe.th32ParentProcessID;
                            string name = pe.szExeFile;
                            tempTree[pid] = (name, ppid);
                        } while (Process32Next(snapshot, ref pe));
                    }

                    _processTree.Clear();
                    foreach (var kvp in tempTree)
                    {
                        _processTree[kvp.Key] = kvp.Value;
                    }
                    _lastTreeRefresh = DateTime.Now;
                }
                catch { }
                finally
                {
                    CloseHandle(snapshot);
                }
            }
        }

        public static (string ParentName, int? ParentPid) GetParentProcess(int pid)
        {
            if (pid <= 0) return ("System", null);

            lock (_treeLock)
            {
                if ((DateTime.Now - _lastTreeRefresh).TotalSeconds > 2 || !_processTree.ContainsKey(pid))
                {
                    RefreshProcessTree();
                }

                if (_processTree.TryGetValue(pid, out var current))
                {
                    int ppid = current.PPid;
                    if (ppid > 0)
                    {
                        if (_processTree.TryGetValue(ppid, out var parentInfo))
                        {
                            string parentName = parentInfo.Name;

                            // Check if spawned through a shell by an automation caller (e.g. Antigravity -> powershell -> python)
                            if ((parentName.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase) ||
                                parentName.Equals("pwsh.exe", StringComparison.OrdinalIgnoreCase) ||
                                parentName.Equals("cmd.exe", StringComparison.OrdinalIgnoreCase)) &&
                                parentInfo.PPid > 0 &&
                                _processTree.TryGetValue(parentInfo.PPid, out var grandParent))
                            {
                                if (!grandParent.Name.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase) &&
                                    !grandParent.Name.Equals("services.exe", StringComparison.OrdinalIgnoreCase))
                                {
                                    return ($"{grandParent.Name} (parentInfo.PPid)", parentInfo.PPid);
                                }
                            }

                            return (parentName, ppid);
                        }

                        try
                        {
                            using var proc = Process.GetProcessById(ppid);
                            return (proc.ProcessName + ".exe", ppid);
                        }
                        catch { }

                        return ($"PID {ppid}", ppid);
                    }
                }
            }

            return ("System", null);
        }

        public static string GetProcessUser(int pid)
        {
            try
            {
                return Environment.UserName;
            }
            catch
            {
                return "SYSTEM";
            }
        }
    }
}
