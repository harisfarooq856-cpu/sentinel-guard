using System;
using System.IO;
using System.Windows;

namespace SentinelGuard
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            DispatcherUnhandledException += (s, args) =>
            {
                args.Handled = true;
                try
                {
                    string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelGuard");
                    Directory.CreateDirectory(dir);
                    File.WriteAllText(Path.Combine(dir, "dispatcher_error.txt"), args.Exception.ToString());
                }
                catch { }
            };

            AppDomain.CurrentDomain.UnhandledException += (s, args) =>
            {
                try
                {
                    string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelGuard");
                    Directory.CreateDirectory(dir);
                    File.WriteAllText(Path.Combine(dir, "startup_error.txt"), args.ExceptionObject.ToString());
                }
                catch { }
            };
            base.OnStartup(e);
        }
    }
}
