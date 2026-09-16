using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using SentinelGuard.Models;

namespace SentinelGuard.Services
{
    public class SentinelEngine
    {
        public DatabaseService Db { get; }
        public QuarantineService Quarantine { get; }
        public NetworkWatcherService Network { get; }
        public ProcessWatcherService Processes { get; }
        public RegistryWatcherService Registry { get; }
        public NotificationService Notifier { get; }

        public event Action<SecurityEvent>? OnSecurityEvent;

        private CancellationTokenSource? _cts;
        private readonly HashSet<string> _seenSockets = new();

        public SentinelEngine(string? dbPath = null)
        {
            Db = new DatabaseService(dbPath);
            Quarantine = new QuarantineService(Db);
            Network = new NetworkWatcherService();
            Processes = new ProcessWatcherService();
            Registry = new RegistryWatcherService();
            Notifier = new NotificationService();
        }

        public void Start()
        {
            _cts = new CancellationTokenSource();
            Task.Run(() => NetworkMonitorLoop(_cts.Token));
        }

        public void Stop()
        {
            _cts?.Cancel();
        }

        private async Task NetworkMonitorLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var conns = Network.GetActiveTcpConnections(Db);
                    foreach (var c in conns)
                    {
                        string key = $"{c.Pid}_{c.RemoteEndpoint}";
                        if (!_seenSockets.Contains(key))
                        {
                            _seenSockets.Add(key);
                            if (c.Risk >= RiskLevel.HIGH)
                            {
                                if (!Db.IsWhitelisted(c.Path, c.ProcessName, c.RemoteIp, parentName: c.ParentProcessName))
                                {
                                    var ev = new SecurityEvent
                                    {
                                        EventType = "NETWORK_CONNECTION",
                                        Name = c.ProcessName,
                                        Pid = c.Pid,
                                        ParentProcessName = c.ParentProcessName,
                                        ParentPid = c.ParentPid,
                                        UserName = c.UserName,
                                        Path = c.Path,
                                        RemoteIp = c.RemoteIp,
                                        RemotePort = c.RemotePort,
                                        Risk = c.Risk,
                                        Details = $"Suspicious background connection to {c.RemoteEndpoint}"
                                    };
                                    Db.AddEvent(ev);
                                    Notifier.Alert(ev);
                                    OnSecurityEvent?.Invoke(ev);
                            }
                        }
                    }
                }
            }
            catch { }

            await Task.Delay(2500, ct);
            }
        }
    }
}
