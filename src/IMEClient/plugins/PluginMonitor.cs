using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace IMEClient.plugins
{
    /// <summary>
    /// Owns a single FileSystemWatcher on C:\ and dispatches every event
    /// to all registered plugins. Each plugin decides whether to act.
    /// </summary>
    internal class PluginMonitor
    {
        private readonly List<InstallerPlugin> _plugins = [];

        public int PluginCount => _plugins.Count;

        public void Add(InstallerPlugin plugin)
        {
            _plugins.Add(plugin);
        }

        /// <summary>Start monitoring and block until cancellation.</summary>
        public void Run(CancellationToken ct = default)
        {
            if (_plugins.Count == 0)
                throw new InvalidOperationException("No plugins registered.");

            // https://x.com/tiraniddo/status/1231999810665734147
            var watcher = new FileSystemWatcher
            {
                Path = @"C:\",
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName,
                IncludeSubdirectories = true
            };

            watcher.Created += Dispatch;
            watcher.Deleted += Dispatch;
            watcher.Changed += Dispatch;

            watcher.EnableRaisingEvents = true;

            Console.WriteLine($"[Monitor] Watching C:\\ with {_plugins.Count} plugin(s):");
            foreach (var p in _plugins)
                Console.WriteLine($"  - {p.Name}");

            if (ct.CanBeCanceled)
                ct.WaitHandle.WaitOne();
            else
                Thread.Sleep(Timeout.Infinite);
        }

        private void Dispatch(object sender, FileSystemEventArgs e)
        {
            foreach (var plugin in _plugins)
            {
                try
                {
                    plugin.OnFileEvent(sender, e);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[{plugin.Name}] Unhandled error: {ex.Message}");
                }
            }
        }
    }
}
