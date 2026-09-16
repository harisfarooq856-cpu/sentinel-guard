using System;
using System.IO;
using System.Net;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using SentinelGuard.Models;

namespace SentinelGuard.Services
{
    public class NetworkWatcherService
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, uint ulAf, TCP_TABLE_CLASS TableClass, uint Reserved = 0);

        private enum TCP_TABLE_CLASS
        {
            TCP_TABLE_OWNER_PID_ALL = 5
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public byte localPort1;
            public byte localPort2;
            public byte localPort3;
            public byte localPort4;
            public uint remoteAddr;
            public byte remotePort1;
            public byte remotePort2;
            public byte remotePort3;
            public byte remotePort4;
            public int owningPid;

            public int LocalPort => (localPort1 << 8) + localPort2;
            public int RemotePort => (remotePort1 << 8) + remotePort2;
        }

        public List<NetworkSocketInfo> GetActiveTcpConnections(DatabaseService? db = null)
        {
            var results = new List<NetworkSocketInfo>();
            int bufferSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);

            IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
            try
            {
                uint ret = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
                if (ret != 0) return results;

                int numEntries = Marshal.ReadInt32(tcpTablePtr);
                IntPtr rowPtr = (IntPtr)((long)tcpTablePtr + 4);
                int row = 1;

                for (int i = 0; i < numEntries; i++)
                {
                    var tcpRow = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf<MIB_TCPROW_OWNER_PID>());

                    string localIp = new IPAddress(tcpRow.localAddr).ToString();
                    string remoteIp = new IPAddress(tcpRow.remoteAddr).ToString();
                    string pName = "System";
                    string pPath = "";

                    try
                    {
                        using var p = Process.GetProcessById(tcpRow.owningPid);
                        pName = p.ProcessName + ".exe";
                        try { pPath = p.MainModule?.FileName ?? ""; } catch { }
                    }
                    catch { }

                    var (parentName, parentPid) = ProcessInfoHelper.GetParentProcess(tcpRow.owningPid);
                    string user = ProcessInfoHelper.GetProcessUser(tcpRow.owningPid);

                    RiskLevel risk = RiskLevel.INFO;
                    if (db != null && db.IsWhitelisted(pPath, pName, remoteIp, parentName: parentName))
                    {
                        risk = RiskLevel.SAFE;
                    }
                    else
                    {
                        var (analyzedRisk, _) = ThreatAnalyzer.AnalyzeNetwork(pName, pPath, remoteIp, tcpRow.RemotePort);
                        risk = analyzedRisk;
                    }

                    results.Add(new NetworkSocketInfo
                    {
                        RowNumber = row++,
                        ProcessName = pName,
                        Pid = tcpRow.owningPid,
                        ParentProcessName = parentName,
                        ParentPid = parentPid,
                        UserName = user,
                        LocalEndpoint = $"{localIp}:{tcpRow.LocalPort}",
                        RemoteEndpoint = $"{remoteIp}:{tcpRow.RemotePort}",
                        RemoteIp = remoteIp,
                        RemotePort = tcpRow.RemotePort,
                        Protocol = "TCP",
                        State = "ESTABLISHED",
                        Risk = risk,
                        Path = pPath
                    });
                }
            }
            finally
            {
                Marshal.FreeHGlobal(tcpTablePtr);
            }
            return results;
        }
    }
}
