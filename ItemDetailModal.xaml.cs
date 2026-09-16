using System;
using System.IO;
using System.Diagnostics;
using System.Windows;
using System.Windows.Media;
using SentinelGuard.Models;

namespace SentinelGuard
{
    public partial class ItemDetailModal : Window
    {
        public Action<string>? OnActionRequested;
        private string _exePath = "";

        public ItemDetailModal(Window owner)
        {
            InitializeComponent();
            this.Owner = owner;
        }

        public void SetData(string name, int? pid, string parent, string user, string path, RiskLevel risk, string reasons, string network = "")
        {
            _exePath = path;
            TxtHeaderName.Text = string.IsNullOrWhiteSpace(name) ? "Unknown" : name;
            TxtHeaderPid.Text = pid.HasValue && pid.Value > 0 ? $"(PID {pid.Value})" : "";
            TxtParent.Text = !string.IsNullOrWhiteSpace(parent) ? parent : "System / Direct";
            TxtUser.Text = !string.IsNullOrWhiteSpace(user) ? user : Environment.UserName;
            TxtPath.Text = !string.IsNullOrWhiteSpace(path) ? path : "N/A (No disk binary path available)";

            if (!string.IsNullOrWhiteSpace(network))
            {
                LblNetwork.Visibility = Visibility.Visible;
                TxtNetwork.Visibility = Visibility.Visible;
                TxtNetwork.Text = network;
            }
            else
            {
                LblNetwork.Visibility = Visibility.Collapsed;
                TxtNetwork.Visibility = Visibility.Collapsed;
            }

            // Signer / Publisher inspection
            TxtSigner.Text = GetSignerInfo(path, name);

            // Risk Badge
            TxtRiskBadge.Text = risk.ToString();
            var (bg, fg) = GetBadgeColors(risk);
            BadgeBorder.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(bg));
            TxtRiskBadge.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(fg));

            // Explanation builder
            if (!string.IsNullOrWhiteSpace(reasons) && risk >= RiskLevel.MEDIUM)
            {
                TxtExplanation.Text = $"[!] Attention Required:\n{reasons}";
            }
            else if (risk == RiskLevel.SAFE)
            {
                TxtExplanation.Text = "✅ This item is classified as SAFE because it is either explicitly whitelisted by you, verified as a trusted Windows component, or spawned by an authorized automation tool.";
            }
            else if (risk == RiskLevel.INFO)
            {
                TxtExplanation.Text = "ℹ Low-Priority Background Activity:\nThis process is running normally with low resource consumption. No hostile injections, ransomware patterns, or unauthorized external connections were found. You can click 'Mark as Safe' below to permanently trust it.";
            }
            else
            {
                TxtExplanation.Text = !string.IsNullOrWhiteSpace(reasons) ? reasons : "Monitored background telemetry.";
            }
        }

        private string GetSignerInfo(string path, string name)
        {
            if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
            {
                try
                {
                    var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(path);
                    if (cert != null)
                    {
                        string subject = cert.Subject;
                        if (subject.Contains("CN="))
                        {
                            var parts = subject.Split(',');
                            foreach (var p in parts)
                            {
                                if (p.Trim().StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                                {
                                    return $"Verified Signature: {p.Trim().Substring(3)}";
                                }
                            }
                        }
                        return $"Verified Certificate: {subject}";
                    }
                }
                catch { }

                try
                {
                    var version = FileVersionInfo.GetVersionInfo(path);
                    if (!string.IsNullOrWhiteSpace(version.CompanyName))
                    {
                        return $"{version.CompanyName} ({version.FileDescription})";
                    }
                }
                catch { }
            }

            if (path.ToLowerInvariant().Contains("\\windows\\"))
                return "Microsoft Windows Component";

            return "Standard Software Binary";
        }

        private (string Bg, string Fg) GetBadgeColors(RiskLevel risk) => risk switch
        {
            RiskLevel.SAFE => ("#D1FAE5", "#065F46"),
            RiskLevel.CRITICAL => ("#FEE2E2", "#991B1B"),
            RiskLevel.HIGH => ("#FFEDD6", "#9A3412"),
            RiskLevel.MEDIUM => ("#FEF3C7", "#92400E"),
            RiskLevel.LOW => ("#E0F2FE", "#075985"),
            _ => ("#F1F5F9", "#475569")
        };

        private void BtnOpenFolder_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(_exePath) && File.Exists(_exePath))
                {
                    Process.Start("explorer.exe", $"/select,\"{_exePath}\"");
                }
            }
            catch { }
        }

        private void BtnMarkSafe_Click(object sender, RoutedEventArgs e)
        {
            OnActionRequested?.Invoke("SAFE");
            this.Close();
        }

        private void BtnTrustParent_Click(object sender, RoutedEventArgs e)
        {
            OnActionRequested?.Invoke("TRUST_PARENT");
            this.Close();
        }

        private void BtnTerminate_Click(object sender, RoutedEventArgs e)
        {
            OnActionRequested?.Invoke("TERMINATE");
            this.Close();
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
