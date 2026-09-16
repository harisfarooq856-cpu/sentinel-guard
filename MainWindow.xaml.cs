using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using SentinelGuard.Models;
using SentinelGuard.Services;

namespace SentinelGuard
{
    public partial class MainWindow : Window
    {
        private readonly SentinelEngine _engine;
        private readonly DispatcherTimer _telemetryTimer;
        private bool _isStreaming = false;

        private readonly List<SecurityEvent> _allEvents = new();
        private readonly List<NetworkSocketInfo> _allSockets = new();
        private readonly List<ProcessItem> _allProcs = new();
        private readonly List<InstalledApp> _allApps = new();
        private readonly List<StartupEntry> _allStartups = new();

        private readonly ObservableCollection<SecurityEvent> _viewEvents = new();
        private readonly ObservableCollection<NetworkSocketInfo> _viewSockets = new();
        private readonly ObservableCollection<ProcessItem> _viewProcs = new();
        private readonly ObservableCollection<InstalledApp> _viewApps = new();
        private readonly ObservableCollection<StartupEntry> _viewStartups = new();
        private readonly ObservableCollection<QuarantineItem> _quarantines = new();
        private readonly ObservableCollection<WhitelistRule> _whitelists = new();

        public MainWindow()
        {
            InitializeComponent();
            EnsureWindowFitsScreen();
            LoadAppIconSafe();
            _engine = new SentinelEngine();

            GridEvents.ItemsSource = _viewEvents;
            GridNetwork.ItemsSource = _viewSockets;
            GridProcs.ItemsSource = _viewProcs;
            GridApps.ItemsSource = _viewApps;
            GridStartup.ItemsSource = _viewStartups;
            GridQuarantine.ItemsSource = _quarantines;
            GridWhitelist.ItemsSource = _whitelists;

            _engine.OnSecurityEvent += Engine_OnSecurityEvent;
            _engine.Start();

            LoadInitialData();

            _telemetryTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(2000)
            };
            _telemetryTimer.Tick += async (s, e) => await StreamTelemetryAsync();
            _telemetryTimer.Start();
        }

        private void EnsureWindowFitsScreen()
        {
            try
            {
                var workArea = SystemParameters.WorkArea;
                if (this.Width > workArea.Width) this.Width = Math.Max(850, workArea.Width - 24);
                if (this.Height > workArea.Height) this.Height = Math.Max(450, workArea.Height - 34);
                this.Left = workArea.Left + Math.Max(0, (workArea.Width - this.Width) / 2);
                this.Top = workArea.Top + Math.Max(0, (workArea.Height - this.Height) / 2);
            }
            catch { }
        }

        private void BtnMin_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }

        private void BtnMax_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = this.WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void LoadAppIconSafe()
        {
            try
            {
                string iconPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "app_icon.ico");
                if (System.IO.File.Exists(iconPath))
                {
                    var uri = new Uri(iconPath, UriKind.Absolute);
                    var bitmap = new System.Windows.Media.Imaging.BitmapImage(uri);
                    this.Icon = bitmap;
                    ImgAppLogo.Source = bitmap;
                    return;
                }

                var resUri = new Uri("pack://application:,,,/app_icon.ico", UriKind.RelativeOrAbsolute);
                var resBitmap = new System.Windows.Media.Imaging.BitmapImage(resUri);
                this.Icon = resBitmap;
                ImgAppLogo.Source = resBitmap;
            }
            catch
            {
                // Fail-safe protection: ensures the application never crashes on icon loading
            }
        }

        private void Engine_OnSecurityEvent(SecurityEvent ev)
        {
            Dispatcher.Invoke(() =>
            {
                _allEvents.Insert(0, ev);
                RenumberEvents();
                ApplyEventsFilter();
                UpdateThreatCount();
            });
        }

        private void RenumberEvents()
        {
            for (int i = 0; i < _allEvents.Count; i++)
            {
                _allEvents[i].RowNumber = i + 1;
            }
        }

        private void UpdateThreatCount()
        {
            TxtThreatsCount.Text = _allEvents.Count(x => x.Risk != RiskLevel.SAFE && x.Risk != RiskLevel.INFO).ToString();
        }

        private void LoadInitialData()
        {
            _allEvents.Clear();
            _allEvents.AddRange(_engine.Db.GetEvents());
            RenumberEvents();
            ApplyEventsFilter();
            UpdateThreatCount();

            _ = StreamTelemetryAsync();
            RefreshApps();
            RefreshStartup();
            RefreshQuarantine();
            RefreshWhitelist();
        }

        private async Task StreamTelemetryAsync()
        {
            if (_isStreaming) return;
            _isStreaming = true;

            try
            {
                var socks = await Task.Run(() => _engine.Network.GetActiveTcpConnections(_engine.Db));
                var procs = await Task.Run(() => _engine.Processes.GetAllProcesses(_engine.Db));

                for (int i = 0; i < socks.Count; i++) socks[i].RowNumber = i + 1;
                for (int i = 0; i < procs.Count; i++) procs[i].RowNumber = i + 1;

                _allSockets.Clear();
                _allSockets.AddRange(socks);
                ApplyNetworkFilter();
                TxtSocketsCount.Text = _allSockets.Count.ToString();

                _allProcs.Clear();
                _allProcs.AddRange(procs);
                ApplyProcsFilter();
                TxtProcsCount.Text = _allProcs.Count.ToString();
            }
            catch { }
            finally
            {
                _isStreaming = false;
            }
        }

        private void TxtSearchEvents_TextChanged(object sender, TextChangedEventArgs e) => ApplyEventsFilter();
        private void TxtSearchNetwork_TextChanged(object sender, TextChangedEventArgs e) => ApplyNetworkFilter();
        private void TxtSearchProcs_TextChanged(object sender, TextChangedEventArgs e) => ApplyProcsFilter();
        private void TxtSearchApps_TextChanged(object sender, TextChangedEventArgs e) => ApplyAppsFilter();
        private void TxtSearchStartup_TextChanged(object sender, TextChangedEventArgs e) => ApplyStartupFilter();

        private void ApplyEventsFilter()
        {
            string q = TxtSearchEvents.Text.Trim().ToLowerInvariant();
            _viewEvents.Clear();
            var filtered = string.IsNullOrEmpty(q) ? _allEvents : _allEvents.Where(x => 
                x.Name.ToLowerInvariant().Contains(q) ||
                x.ParentProcessName.ToLowerInvariant().Contains(q) ||
                x.Details.ToLowerInvariant().Contains(q) ||
                x.UserName.ToLowerInvariant().Contains(q) ||
                (x.Pid.HasValue && x.Pid.Value.ToString().Contains(q)));
            foreach (var e in filtered) _viewEvents.Add(e);
        }

        private void ApplyNetworkFilter()
        {
            string q = TxtSearchNetwork.Text.Trim().ToLowerInvariant();
            _viewSockets.Clear();
            var filtered = string.IsNullOrEmpty(q) ? _allSockets : _allSockets.Where(x => 
                x.ProcessName.ToLowerInvariant().Contains(q) ||
                x.RemoteEndpoint.ToLowerInvariant().Contains(q) ||
                x.ParentProcessName.ToLowerInvariant().Contains(q) ||
                x.UserName.ToLowerInvariant().Contains(q) ||
                x.Pid.ToString().Contains(q));
            foreach (var s in filtered) _viewSockets.Add(s);
        }

        private void ApplyProcsFilter()
        {
            string q = TxtSearchProcs.Text.Trim().ToLowerInvariant();
            _viewProcs.Clear();
            var filtered = string.IsNullOrEmpty(q) ? _allProcs : _allProcs.Where(x => 
                x.Name.ToLowerInvariant().Contains(q) ||
                x.ParentProcessName.ToLowerInvariant().Contains(q) ||
                x.UserName.ToLowerInvariant().Contains(q) ||
                x.ExePath.ToLowerInvariant().Contains(q) ||
                x.Pid.ToString().Contains(q));
            foreach (var p in filtered) _viewProcs.Add(p);
        }

        private void ApplyAppsFilter()
        {
            string q = TxtSearchApps.Text.Trim().ToLowerInvariant();
            _viewApps.Clear();
            var filtered = string.IsNullOrEmpty(q) ? _allApps : _allApps.Where(x => 
                x.Name.ToLowerInvariant().Contains(q) ||
                x.Publisher.ToLowerInvariant().Contains(q));
            foreach (var a in filtered) _viewApps.Add(a);
        }

        private void ApplyStartupFilter()
        {
            string q = TxtSearchStartup.Text.Trim().ToLowerInvariant();
            _viewStartups.Clear();
            var filtered = string.IsNullOrEmpty(q) ? _allStartups : _allStartups.Where(x => 
                x.Name.ToLowerInvariant().Contains(q) ||
                x.Command.ToLowerInvariant().Contains(q));
            foreach (var s in filtered) _viewStartups.Add(s);
        }

        private void RefreshApps()
        {
            _allApps.Clear();
            _allApps.AddRange(_engine.Registry.GetAllInstalledSoftware());
            ApplyAppsFilter();
            TxtAppsCount.Text = _allApps.Count.ToString();
        }

        private void RefreshStartup()
        {
            _allStartups.Clear();
            _allStartups.AddRange(_engine.Registry.GetAllStartupEntries());
            ApplyStartupFilter();
        }

        private void RefreshQuarantine()
        {
            _quarantines.Clear();
            var qs = _engine.Db.GetQuarantinedFiles();
            for (int i = 0; i < qs.Count; i++)
            {
                qs[i].RowNumber = i + 1;
                _quarantines.Add(qs[i]);
            }
        }

        private void RefreshWhitelist()
        {
            _whitelists.Clear();
            var ws = _engine.Db.GetWhitelist();
            for (int i = 0; i < ws.Count; i++)
            {
                ws[i].RowNumber = i + 1;
                _whitelists.Add(ws[i]);
            }
        }

        private void NavBtn_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && int.TryParse(btn.Tag?.ToString(), out int index))
            {
                SwitchTab(index);
            }
        }

        private void SwitchTab(int index)
        {
            TabAlerts.Visibility = index == 0 ? Visibility.Visible : Visibility.Collapsed;
            TabNetwork.Visibility = index == 1 ? Visibility.Visible : Visibility.Collapsed;
            TabProcs.Visibility = index == 2 ? Visibility.Visible : Visibility.Collapsed;
            TabApps.Visibility = index == 3 ? Visibility.Visible : Visibility.Collapsed;
            TabStartup.Visibility = index == 4 ? Visibility.Visible : Visibility.Collapsed;
            TabQuarantine.Visibility = index == 5 ? Visibility.Visible : Visibility.Collapsed;
            TabSettings.Visibility = index == 6 ? Visibility.Visible : Visibility.Collapsed;

            Button[] navs = new[] { NavBtnAlerts, NavBtnNetwork, NavBtnProcs, NavBtnApps, NavBtnStartup, NavBtnQuarantine, NavBtnSettings };
            for (int i = 0; i < navs.Length; i++)
            {
                if (i == index)
                {
                    navs[i].Background = (Brush)new BrushConverter().ConvertFromString("#EFF6FF")!;
                    navs[i].Foreground = (Brush)new BrushConverter().ConvertFromString("#2563EB")!;
                }
                else
                {
                    navs[i].Background = Brushes.Transparent;
                    navs[i].Foreground = (Brush)new BrushConverter().ConvertFromString("#475569")!;
                }
            }
        }

        // =========== TOP TOOLBAR ALERTS / THREATS ===========
        private void MarkEventSafe_Click(object sender, RoutedEventArgs e)
        {
            if (GridEvents.SelectedItem is SecurityEvent ev)
            {
                string type = !string.IsNullOrWhiteSpace(ev.Path) ? "PATH" : "NAME";
                string val = !string.IsNullOrWhiteSpace(ev.Path) ? ev.Path : ev.Name;
                _engine.Db.AddWhitelist(type, val, "Marked Safe from Toolbar");
                ev.Risk = RiskLevel.SAFE;
                GridEvents.Items.Refresh();
                RefreshWhitelist();
                UpdateThreatCount();
                MessageBox.Show($"{val} has been marked as SAFE and whitelisted.", "Sentinel Whitelist", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void TrustParentEvent_Click(object sender, RoutedEventArgs e)
        {
            if (GridEvents.SelectedItem is SecurityEvent ev)
            {
                TrustParentAutomation(ev.ParentProcessName, ev.Name);
            }
        }

        private void RowEventTrustParent_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is SecurityEvent ev)
            {
                TrustParentAutomation(ev.ParentProcessName, ev.Name);
            }
        }

        private void ClearOldEvents_Click(object sender, RoutedEventArgs e)
        {
            var res = MessageBox.Show("Clear historical events from previous sessions?\nActive live protection will continue logging fresh events.", "Clear Event Log", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (res == MessageBoxResult.Yes)
            {
                _engine.Db.ClearEvents();
                _allEvents.Clear();
                _viewEvents.Clear();
                RenumberEvents();
                UpdateThreatCount();
            }
        }

        private void TrustParentNetwork_Click(object sender, RoutedEventArgs e)
        {
            if (GridNetwork.SelectedItem is NetworkSocketInfo sock)
            {
                TrustParentAutomation(sock.ParentProcessName, sock.ProcessName);
            }
        }

        private void RowNetworkTrustParent_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is NetworkSocketInfo sock)
            {
                TrustParentAutomation(sock.ParentProcessName, sock.ProcessName);
            }
        }

        private void TrustParentProc_Click(object sender, RoutedEventArgs e)
        {
            if (GridProcs.SelectedItem is ProcessItem p)
            {
                TrustParentAutomation(p.ParentProcessName, p.Name);
            }
        }

        private void RowProcTrustParent_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is ProcessItem p)
            {
                TrustParentAutomation(p.ParentProcessName, p.Name);
            }
        }

        private void TrustParentAutomation(string rawParentName, string childName)
        {
            if (string.IsNullOrWhiteSpace(rawParentName) || 
                rawParentName.Equals("System", StringComparison.OrdinalIgnoreCase) ||
                rawParentName.Equals("System / Direct", StringComparison.OrdinalIgnoreCase))
            {
                MessageBox.Show("No external parent automation process detected for this item.", "Sentinel Trust", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            string parentTool = rawParentName;
            if (parentTool.Contains("➔"))
            {
                parentTool = parentTool.Split('➔')[0].Trim();
            }
            if (parentTool.Contains("("))
            {
                parentTool = parentTool.Split('(')[0].Trim();
            }

            _engine.Db.AddWhitelist("NAME", parentTool, $"Trusted Automation Parent: {parentTool}");
            if (!string.IsNullOrWhiteSpace(childName) && !childName.Equals(parentTool, StringComparison.OrdinalIgnoreCase))
            {
                _engine.Db.AddWhitelist("NAME", childName, $"Child spawned by {parentTool}");
            }

            foreach (var ev in _allEvents)
            {
                if (ev.ParentProcessName.Contains(parentTool, StringComparison.OrdinalIgnoreCase) || ev.Name.Equals(parentTool, StringComparison.OrdinalIgnoreCase))
                {
                    ev.Risk = RiskLevel.SAFE;
                }
            }
            foreach (var s in _allSockets)
            {
                if (s.ParentProcessName.Contains(parentTool, StringComparison.OrdinalIgnoreCase) || s.ProcessName.Equals(parentTool, StringComparison.OrdinalIgnoreCase))
                {
                    s.Risk = RiskLevel.SAFE;
                }
            }
            foreach (var p in _allProcs)
            {
                if (p.ParentProcessName.Contains(parentTool, StringComparison.OrdinalIgnoreCase) || p.Name.Equals(parentTool, StringComparison.OrdinalIgnoreCase))
                {
                    p.Risk = RiskLevel.SAFE;
                }
            }

            GridEvents.Items.Refresh();
            GridNetwork.Items.Refresh();
            GridProcs.Items.Refresh();
            RefreshWhitelist();
            UpdateThreatCount();
            _ = StreamTelemetryAsync();

            MessageBox.Show($"Automation tool '{parentTool}' has been permanently whitelisted!\n\nAll child scripts, tasks, and network connections spawned by it are now marked as SAFE everywhere across the dashboard.", "Sentinel Trust Automation", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void TerminateEventProc_Click(object sender, RoutedEventArgs e)
        {
            if (GridEvents.SelectedItem is SecurityEvent ev && ev.Pid.HasValue && ev.Pid.Value > 0)
            {
                bool ok = _engine.Processes.TerminateProcess(ev.Pid.Value);
                MessageBox.Show(ok ? $"Process {ev.Name} (PID {ev.Pid}) terminated." : "Failed to terminate process.", "Sentinel Defense", MessageBoxButton.OK, ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
                _ = StreamTelemetryAsync();
            }
        }

        private void QuarantineEvent_Click(object sender, RoutedEventArgs e)
        {
            if (GridEvents.SelectedItem is SecurityEvent ev && !string.IsNullOrWhiteSpace(ev.Path))
            {
                bool ok = _engine.Quarantine.QuarantineFile(ev.Path, $"Quarantined from alert {ev.EventType}");
                MessageBox.Show(ok ? $"File {ev.Path} isolated into Quarantine Vault." : "Failed to quarantine file.", "Quarantine Vault", MessageBoxButton.OK);
                RefreshQuarantine();
            }
        }

        private void DismissEvent_Click(object sender, RoutedEventArgs e)
        {
            if (GridEvents.SelectedItem is SecurityEvent ev)
            {
                _allEvents.Remove(ev);
                _viewEvents.Remove(ev);
                RenumberEvents();
                UpdateThreatCount();
            }
        }

        // =========== INLINE ROW ACTIONS FOR LIVE THREATS ===========
        private void RowEventSafe_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is SecurityEvent ev)
            {
                string type = !string.IsNullOrWhiteSpace(ev.Path) ? "PATH" : "NAME";
                string val = !string.IsNullOrWhiteSpace(ev.Path) ? ev.Path : ev.Name;
                _engine.Db.AddWhitelist(type, val, "Marked Safe from Quick Action");
                ev.Risk = RiskLevel.SAFE;
                GridEvents.Items.Refresh();
                RefreshWhitelist();
                UpdateThreatCount();
            }
        }

        private void RowEventKill_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is SecurityEvent ev && ev.Pid.HasValue && ev.Pid.Value > 0)
            {
                bool ok = _engine.Processes.TerminateProcess(ev.Pid.Value);
                MessageBox.Show(ok ? $"Process {ev.Name} (PID {ev.Pid}) terminated." : "Failed to terminate process.", "Sentinel Defense", MessageBoxButton.OK, ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
                _ = StreamTelemetryAsync();
            }
        }

        private void RowEventQuarantine_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is SecurityEvent ev && !string.IsNullOrWhiteSpace(ev.Path))
            {
                bool ok = _engine.Quarantine.QuarantineFile(ev.Path, $"Quarantined from alert {ev.EventType}");
                MessageBox.Show(ok ? $"File {ev.Path} isolated into Quarantine Vault." : "Failed to quarantine file.", "Quarantine Vault", MessageBoxButton.OK);
                RefreshQuarantine();
            }
        }

        private void RowEventDismiss_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is SecurityEvent ev)
            {
                _allEvents.Remove(ev);
                _viewEvents.Remove(ev);
                RenumberEvents();
                UpdateThreatCount();
            }
        }

        // =========== NETWORK & SOCKETS ACTIONS ===========
        private void MarkNetworkSafe_Click(object sender, RoutedEventArgs e)
        {
            if (GridNetwork.SelectedItem is NetworkSocketInfo sock)
            {
                _engine.Db.AddWhitelist("NAME", sock.ProcessName, "Marked Safe from Network");
                sock.Risk = RiskLevel.SAFE;
                GridNetwork.Items.Refresh();
                RefreshWhitelist();
                MessageBox.Show($"Process {sock.ProcessName} has been marked as SAFE.", "Sentinel Whitelist", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void KillSocket_Click(object sender, RoutedEventArgs e)
        {
            if (GridNetwork.SelectedItem is NetworkSocketInfo sock)
            {
                bool ok = _engine.Processes.TerminateProcess(sock.Pid);
                MessageBox.Show(ok ? $"Process {sock.ProcessName} (PID {sock.Pid}) terminated." : "Failed to terminate process.", "Network Defense", MessageBoxButton.OK, ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
                _ = StreamTelemetryAsync();
            }
        }

        private void RefreshNetwork_Click(object sender, RoutedEventArgs e) => _ = StreamTelemetryAsync();

        private void RowNetworkSafe_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is NetworkSocketInfo sock)
            {
                _engine.Db.AddWhitelist("NAME", sock.ProcessName, "Marked Safe from Quick Action");
                sock.Risk = RiskLevel.SAFE;
                GridNetwork.Items.Refresh();
                RefreshWhitelist();
            }
        }

        private void RowNetworkKill_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is NetworkSocketInfo sock)
            {
                bool ok = _engine.Processes.TerminateProcess(sock.Pid);
                MessageBox.Show(ok ? $"Process {sock.ProcessName} (PID {sock.Pid}) terminated." : "Failed to terminate process.", "Network Defense", MessageBoxButton.OK, ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
                _ = StreamTelemetryAsync();
            }
        }

        // =========== PROCESSES ACTIONS ===========
        private void MarkProcSafe_Click(object sender, RoutedEventArgs e)
        {
            if (GridProcs.SelectedItem is ProcessItem p)
            {
                _engine.Db.AddWhitelist("NAME", p.Name, "Marked Safe from Processes");
                p.Risk = RiskLevel.SAFE;
                GridProcs.Items.Refresh();
                RefreshWhitelist();
                MessageBox.Show($"Process {p.Name} has been marked as SAFE.", "Sentinel Whitelist", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void TerminateSelectedProc_Click(object sender, RoutedEventArgs e)
        {
            if (GridProcs.SelectedItem is ProcessItem p)
            {
                bool ok = _engine.Processes.TerminateProcess(p.Pid);
                MessageBox.Show(ok ? $"Process {p.Name} (PID {p.Pid}) terminated." : "Failed to terminate process.", "Process Manager", MessageBoxButton.OK, ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
                _ = StreamTelemetryAsync();
            }
        }

        private void RefreshProcs_Click(object sender, RoutedEventArgs e) => _ = StreamTelemetryAsync();

        private void RowProcSafe_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is ProcessItem p)
            {
                _engine.Db.AddWhitelist("NAME", p.Name, "Marked Safe from Quick Action");
                p.Risk = RiskLevel.SAFE;
                GridProcs.Items.Refresh();
                RefreshWhitelist();
            }
        }

        private void RowProcKill_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is ProcessItem p)
            {
                bool ok = _engine.Processes.TerminateProcess(p.Pid);
                MessageBox.Show(ok ? $"Process {p.Name} (PID {p.Pid}) terminated." : "Failed to terminate process.", "Process Manager", MessageBoxButton.OK, ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
                _ = StreamTelemetryAsync();
            }
        }

        private void RowProcQuarantine_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is ProcessItem p && !string.IsNullOrWhiteSpace(p.ExePath))
            {
                _engine.Processes.TerminateProcess(p.Pid);
                bool ok = _engine.Quarantine.QuarantineFile(p.ExePath, $"Quarantined process binary {p.Name}");
                MessageBox.Show(ok ? $"Binary {p.ExePath} quarantined successfully." : "Failed to quarantine binary.", "Quarantine Vault", MessageBoxButton.OK);
                RefreshQuarantine();
                _ = StreamTelemetryAsync();
            }
        }

        // =========== STARTUP, QUARANTINE & WHITELIST ===========
        private void MarkStartupSafe_Click(object sender, RoutedEventArgs e)
        {
            if (GridStartup.SelectedItem is StartupEntry s)
            {
                _engine.Db.AddWhitelist("NAME", s.Name, "Marked Safe from Startup");
                s.Risk = RiskLevel.SAFE;
                GridStartup.Items.Refresh();
                RefreshWhitelist();
                MessageBox.Show($"Startup entry {s.Name} has been marked as SAFE.", "Sentinel Whitelist", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void RestoreQuarantine_Click(object sender, RoutedEventArgs e)
        {
            if (GridQuarantine.SelectedItem is QuarantineItem q)
            {
                bool ok = _engine.Quarantine.RestoreFile(q);
                MessageBox.Show(ok ? $"File restored to {q.OriginalPath}" : "Failed to restore file.", "Quarantine Vault", MessageBoxButton.OK);
                RefreshQuarantine();
            }
        }

        private void DeleteQuarantine_Click(object sender, RoutedEventArgs e)
        {
            if (GridQuarantine.SelectedItem is QuarantineItem q)
            {
                _engine.Quarantine.DeleteQuarantined(q);
                RefreshQuarantine();
            }
        }

        private void AddWhitelist_Click(object sender, RoutedEventArgs e)
        {
            string val = TxtWlValue.Text.Trim();
            if (!string.IsNullOrWhiteSpace(val))
            {
                string type = ((ComboBoxItem)CmbWlType.SelectedItem).Content.ToString() ?? "PATH";
                _engine.Db.AddWhitelist(type, val, "Manual Rule");
                TxtWlValue.Text = "";
                RefreshWhitelist();
            }
        }

        private void DeleteWhitelist_Click(object sender, RoutedEventArgs e)
        {
            if (GridWhitelist.SelectedItem is WhitelistRule rule)
            {
                _engine.Db.RemoveWhitelist(rule.Id);
                RefreshWhitelist();
            }
        }

        // ==================== SECURITY INSPECTOR MODAL ====================
        private void ShowEventDetails(SecurityEvent ev)
        {
            if (ev == null) return;
            var modal = new ItemDetailModal(this);
            string netInfo = !string.IsNullOrWhiteSpace(ev.RemoteIp) ? $"{ev.RemoteIp}:{ev.RemotePort}" : "";
            modal.SetData(ev.Name, ev.Pid, ev.ParentProcessName, ev.DisplayUser, ev.Path, ev.Risk, ev.Details, netInfo);
            modal.OnActionRequested += action =>
            {
                if (action == "SAFE")
                {
                    _engine.Db.AddWhitelist(!string.IsNullOrWhiteSpace(ev.Path) ? "PATH" : "NAME", !string.IsNullOrWhiteSpace(ev.Path) ? ev.Path : ev.Name, "Marked safe from Inspector");
                    ev.Risk = RiskLevel.SAFE;
                    GridEvents.Items.Refresh();
                    RefreshWhitelist();
                    UpdateThreatCount();
                }
                else if (action == "TRUST_PARENT")
                {
                    TrustParentAutomation(ev.ParentProcessName, ev.Name);
                }
                else if (action == "TERMINATE" && ev.Pid.HasValue && ev.Pid.Value > 0)
                {
                    _engine.Processes.TerminateProcess(ev.Pid.Value);
                    _ = StreamTelemetryAsync();
                }
            };
            modal.ShowDialog();
        }

        private void EventRiskBadge_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is SecurityEvent ev) ShowEventDetails(ev);
        }

        private void EventDetailsView_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is SecurityEvent ev) ShowEventDetails(ev);
        }

        private void ShowNetworkDetails(NetworkSocketInfo sock)
        {
            if (sock == null) return;
            var modal = new ItemDetailModal(this);
            modal.SetData(sock.ProcessName, sock.Pid, sock.ParentProcessName, sock.DisplayUser, sock.Path, sock.Risk, $"Active Socket: {sock.Protocol} {sock.LocalEndpoint} -> {sock.RemoteEndpoint} ({sock.State})", sock.RemoteEndpoint);
            modal.OnActionRequested += action =>
            {
                if (action == "SAFE")
                {
                    _engine.Db.AddWhitelist("NAME", sock.ProcessName, "Marked safe from Inspector");
                    sock.Risk = RiskLevel.SAFE;
                    GridNetwork.Items.Refresh();
                    RefreshWhitelist();
                }
                else if (action == "TRUST_PARENT")
                {
                    TrustParentAutomation(sock.ParentProcessName, sock.ProcessName);
                }
                else if (action == "TERMINATE")
                {
                    _engine.Processes.TerminateProcess(sock.Pid);
                    _ = StreamTelemetryAsync();
                }
            };
            modal.ShowDialog();
        }

        private void NetworkRiskBadge_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is NetworkSocketInfo sock) ShowNetworkDetails(sock);
        }

        private void NetworkDetailsView_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is NetworkSocketInfo sock) ShowNetworkDetails(sock);
        }

        private void ShowProcDetails(ProcessItem p)
        {
            if (p == null) return;
            var modal = new ItemDetailModal(this);
            var (_, reasons) = ThreatAnalyzer.AnalyzeProcess(p.Name, p.ExePath);
            modal.SetData(p.Name, p.Pid, p.ParentProcessName, p.DisplayUser, p.ExePath, p.Risk, reasons);
            modal.OnActionRequested += action =>
            {
                if (action == "SAFE")
                {
                    _engine.Db.AddWhitelist("NAME", p.Name, "Marked safe from Inspector");
                    p.Risk = RiskLevel.SAFE;
                    GridProcs.Items.Refresh();
                    RefreshWhitelist();
                }
                else if (action == "TRUST_PARENT")
                {
                    TrustParentAutomation(p.ParentProcessName, p.Name);
                }
                else if (action == "TERMINATE")
                {
                    _engine.Processes.TerminateProcess(p.Pid);
                    _ = StreamTelemetryAsync();
                }
            };
            modal.ShowDialog();
        }

        private void ProcRiskBadge_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is ProcessItem p) ShowProcDetails(p);
        }

        private void ProcDetailsView_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is ProcessItem p) ShowProcDetails(p);
        }

        // ==================== UNIVERSAL BULK ACTIONS ====================
        private void SelectAllAlerts_Click(object sender, RoutedEventArgs e)
        {
            bool isChecked = (sender as CheckBox)?.IsChecked ?? false;
            foreach (var item in _viewEvents) item.IsSelected = isChecked;
            GridEvents.Items.Refresh();
        }

        private void BulkAlertsSafe_Click(object sender, RoutedEventArgs e)
        {
            var selected = _viewEvents.Where(x => x.IsSelected).ToList();
            if (selected.Count == 0) { MessageBox.Show("No items selected. Check one or more rows to perform bulk action.", "Bulk Actions", MessageBoxButton.OK, MessageBoxImage.Information); return; }
            foreach (var ev in selected)
            {
                _engine.Db.AddWhitelist(!string.IsNullOrWhiteSpace(ev.Path) ? "PATH" : "NAME", !string.IsNullOrWhiteSpace(ev.Path) ? ev.Path : ev.Name, "Bulk Marked Safe");
                ev.Risk = RiskLevel.SAFE;
                ev.IsSelected = false;
            }
            GridEvents.Items.Refresh();
            RefreshWhitelist();
            UpdateThreatCount();
            MessageBox.Show($"{selected.Count} alerts marked as SAFE.", "Bulk Operation Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void BulkAlertsTrustParent_Click(object sender, RoutedEventArgs e)
        {
            var selected = _viewEvents.Where(x => x.IsSelected).ToList();
            if (selected.Count == 0) { MessageBox.Show("No items selected. Check one or more rows to perform bulk action.", "Bulk Actions", MessageBoxButton.OK, MessageBoxImage.Information); return; }
            int count = 0;
            foreach (var ev in selected)
            {
                if (!string.IsNullOrWhiteSpace(ev.ParentProcessName) && !ev.ParentProcessName.StartsWith("System", StringComparison.OrdinalIgnoreCase))
                {
                    string clean = ev.ParentProcessName.Split(new[] { '➔', '(' })[0].Trim();
                    _engine.Db.AddWhitelist("NAME", clean, "Bulk Trusted Parent");
                    count++;
                }
                ev.Risk = RiskLevel.SAFE;
                ev.IsSelected = false;
            }
            GridEvents.Items.Refresh();
            RefreshWhitelist();
            UpdateThreatCount();
            MessageBox.Show($"Bulk Whitelisted {count} parent automation tools!\nAll their child processes are now marked SAFE.", "Bulk Operation Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void BulkAlertsKill_Click(object sender, RoutedEventArgs e)
        {
            var selected = _viewEvents.Where(x => x.IsSelected).ToList();
            if (selected.Count == 0) { MessageBox.Show("No items selected. Check one or more rows to perform bulk action.", "Bulk Actions", MessageBoxButton.OK, MessageBoxImage.Information); return; }
            int killed = 0;
            foreach (var ev in selected)
            {
                if (ev.Pid.HasValue && ev.Pid.Value > 0 && _engine.Processes.TerminateProcess(ev.Pid.Value)) killed++;
                ev.IsSelected = false;
            }
            GridEvents.Items.Refresh();
            _ = StreamTelemetryAsync();
            MessageBox.Show($"Terminated {killed} selected processes.", "Bulk Operation Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void BulkAlertsRemove_Click(object sender, RoutedEventArgs e)
        {
            var selected = _viewEvents.Where(x => x.IsSelected).ToList();
            if (selected.Count == 0) { MessageBox.Show("No items selected. Check one or more rows to perform bulk action.", "Bulk Actions", MessageBoxButton.OK, MessageBoxImage.Information); return; }
            foreach (var ev in selected)
            {
                _allEvents.Remove(ev);
                _viewEvents.Remove(ev);
            }
            RenumberEvents();
            UpdateThreatCount();
            GridEvents.Items.Refresh();
        }

        private void SelectAllNetwork_Click(object sender, RoutedEventArgs e)
        {
            bool isChecked = (sender as CheckBox)?.IsChecked ?? false;
            foreach (var item in _viewSockets) item.IsSelected = isChecked;
            GridNetwork.Items.Refresh();
        }

        private void BulkNetworkSafe_Click(object sender, RoutedEventArgs e)
        {
            var selected = _viewSockets.Where(x => x.IsSelected).ToList();
            if (selected.Count == 0) { MessageBox.Show("No network sockets selected.", "Bulk Actions", MessageBoxButton.OK, MessageBoxImage.Information); return; }
            foreach (var s in selected)
            {
                _engine.Db.AddWhitelist("NAME", s.ProcessName, "Bulk Marked Safe");
                s.Risk = RiskLevel.SAFE;
                s.IsSelected = false;
            }
            GridNetwork.Items.Refresh();
            RefreshWhitelist();
            MessageBox.Show($"{selected.Count} network sockets marked as SAFE.", "Bulk Operation Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void BulkNetworkTrustParent_Click(object sender, RoutedEventArgs e)
        {
            var selected = _viewSockets.Where(x => x.IsSelected).ToList();
            if (selected.Count == 0) { MessageBox.Show("No sockets selected.", "Bulk Actions", MessageBoxButton.OK, MessageBoxImage.Information); return; }
            int count = 0;
            foreach (var s in selected)
            {
                if (!string.IsNullOrWhiteSpace(s.ParentProcessName) && !s.ParentProcessName.StartsWith("System", StringComparison.OrdinalIgnoreCase))
                {
                    string clean = s.ParentProcessName.Split(new[] { '➔', '(' })[0].Trim();
                    _engine.Db.AddWhitelist("NAME", clean, "Bulk Trusted Parent");
                    count++;
                }
                s.Risk = RiskLevel.SAFE;
                s.IsSelected = false;
            }
            GridNetwork.Items.Refresh();
            RefreshWhitelist();
            MessageBox.Show($"Bulk Whitelisted {count} parent automation tools!", "Bulk Operation Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void BulkNetworkKill_Click(object sender, RoutedEventArgs e)
        {
            var selected = _viewSockets.Where(x => x.IsSelected).ToList();
            if (selected.Count == 0) { MessageBox.Show("No sockets selected.", "Bulk Actions", MessageBoxButton.OK, MessageBoxImage.Information); return; }
            int killed = 0;
            foreach (var s in selected)
            {
                if (s.Pid > 0 && _engine.Processes.TerminateProcess(s.Pid)) killed++;
                s.IsSelected = false;
            }
            GridNetwork.Items.Refresh();
            _ = StreamTelemetryAsync();
            MessageBox.Show($"Terminated {killed} socket processes.", "Bulk Operation Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void SelectAllProcs_Click(object sender, RoutedEventArgs e)
        {
            bool isChecked = (sender as CheckBox)?.IsChecked ?? false;
            foreach (var item in _viewProcs) item.IsSelected = isChecked;
            GridProcs.Items.Refresh();
        }

        private void BulkProcsSafe_Click(object sender, RoutedEventArgs e)
        {
            var selected = _viewProcs.Where(x => x.IsSelected).ToList();
            if (selected.Count == 0) { MessageBox.Show("No processes selected.", "Bulk Actions", MessageBoxButton.OK, MessageBoxImage.Information); return; }
            foreach (var p in selected)
            {
                _engine.Db.AddWhitelist("NAME", p.Name, "Bulk Marked Safe");
                p.Risk = RiskLevel.SAFE;
                p.IsSelected = false;
            }
            GridProcs.Items.Refresh();
            RefreshWhitelist();
            MessageBox.Show($"{selected.Count} processes marked as SAFE.", "Bulk Operation Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void BulkProcsTrustParent_Click(object sender, RoutedEventArgs e)
        {
            var selected = _viewProcs.Where(x => x.IsSelected).ToList();
            if (selected.Count == 0) { MessageBox.Show("No processes selected.", "Bulk Actions", MessageBoxButton.OK, MessageBoxImage.Information); return; }
            int count = 0;
            foreach (var p in selected)
            {
                if (!string.IsNullOrWhiteSpace(p.ParentProcessName) && !p.ParentProcessName.StartsWith("System", StringComparison.OrdinalIgnoreCase))
                {
                    string clean = p.ParentProcessName.Split(new[] { '➔', '(' })[0].Trim();
                    _engine.Db.AddWhitelist("NAME", clean, "Bulk Trusted Parent");
                    count++;
                }
                p.Risk = RiskLevel.SAFE;
                p.IsSelected = false;
            }
            GridProcs.Items.Refresh();
            RefreshWhitelist();
            MessageBox.Show($"Bulk Whitelisted {count} parent automation tools!", "Bulk Operation Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void BulkProcsKill_Click(object sender, RoutedEventArgs e)
        {
            var selected = _viewProcs.Where(x => x.IsSelected).ToList();
            if (selected.Count == 0) { MessageBox.Show("No processes selected.", "Bulk Actions", MessageBoxButton.OK, MessageBoxImage.Information); return; }
            int killed = 0;
            foreach (var p in selected)
            {
                if (p.Pid > 0 && _engine.Processes.TerminateProcess(p.Pid)) killed++;
                p.IsSelected = false;
            }
            GridProcs.Items.Refresh();
            _ = StreamTelemetryAsync();
            MessageBox.Show($"Terminated {killed} processes.", "Bulk Operation Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}
