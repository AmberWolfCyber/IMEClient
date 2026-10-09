using IMEClient.plugins;
using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace IMEClient
{
    [CallbackBehavior(
        ConcurrencyMode = ConcurrencyMode.Multiple,
        UseSynchronizationContext = false)]
    class StatusServiceCallback : IStatusServiceCallback
    {
        public void SyncComplete(SyncResult result)
        {
            if (result == null) { Log("[CB] SyncComplete: null"); return; }
            var s = result.Success ? "SUCCESS" : $"FAILED (error {result.ErrorCode})";
            Log($"[CB] SyncComplete: session={result.SessionId} {s}");
        }

        public void AppStatusUpdate(AppInstallStatusReport report)
        {
            if (report == null) { Log("[CB] AppStatusUpdate: null"); return; }
            Log($"[CB] AppStatusUpdate: app={report.AppId} status={report.Status2} err={report.ErrorCode}");
        }

        public void DownloadProgressUpdate(DownloadProgressReport report)
        {
            if (report == null) { Log("[CB] DownloadProgress: null"); return; }
            var pct = report.TotalSizeInBytes > 0
                ? $"{report.BytesDownloaded * 100.0 / report.TotalSizeInBytes:F1}%"
                : "?%";
            Log($"[CB] Download: app={report.AppId} {report.BytesDownloaded}/{report.TotalSizeInBytes} ({pct})");
        }

        static void Log(string msg) =>
            Console.WriteLine($"  {DateTime.Now:HH:mm:ss.fff}  {msg}");
    }

    class Program
    {
        const string DefaultPipeEndpoint = "net.pipe://localhost/IntuneManagementExtension/StatusService/";

        static IStatusService _pipe;
        static IClientChannel _channel;
        static IntuneRestClient _rest;

        public static bool Verbose;

        public static List<string> ListPlugins()
        {
            return AppDomain.CurrentDomain.GetAssemblies()
                .SelectMany(a => a.GetTypes())
                .Where(t => typeof(InstallerPlugin).IsAssignableFrom(t) && !t.IsAbstract)
                .Select(t => t.Name)
                .ToList();
        }

        static async Task<int> Main(string[] args)
        {
            return await RunCli(args);
        }

        static void ConnectPipe(string endpoint)
        {
            var binding = new NetNamedPipeBinding(NetNamedPipeSecurityMode.Transport)
            {
                OpenTimeout = TimeSpan.FromSeconds(50),
                SendTimeout = TimeSpan.FromSeconds(30),
                ReceiveTimeout = TimeSpan.FromMinutes(10),
                MaxReceivedMessageSize = 1048576
            };

            var callback = new InstanceContext(new StatusServiceCallback());
            var factory = new DuplexChannelFactory<IStatusService>(callback, binding, new EndpointAddress(endpoint));

            _pipe = factory.CreateChannel();
            _channel = (IClientChannel)_pipe;
            _channel.Faulted += (s, e) => Console.Error.WriteLine("[PIPE] Channel faulted.");
            _channel.Open();
        }

        static void ShowUsage()
        {
            Console.WriteLine("IMEClient - Intune Company Portal CLI");
            Console.WriteLine();
            Console.WriteLine("Usage: IMEClient.exe <command> [options]");
            Console.WriteLine();
            Console.WriteLine("Commands:");
            Console.WriteLine("  list                           List available applications");
            Console.WriteLine("  install <app> [--checkin]       Install an app (by number or GUID)");
            Console.WriteLine("  uninstall <app> [--checkin]     Uninstall an app");
            Console.WriteLine("  states                         Show app states with action targets");
            Console.WriteLine("  search <query>                 Search applications");
            Console.WriteLine("  details <app>                  Show detailed app info and state");
            Console.WriteLine("  monitor <plugin|all> [args...] Run installer exploit plugin(s)");
            Console.WriteLine("  plugins                        List available plugins");
            Console.WriteLine("  checkin                        Trigger IME service sync via named pipe");
            Console.WriteLine("  diag                           Dump token claims");
            Console.WriteLine("  help                           Show this usage info");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --checkin                      Trigger IME named pipe sync after action");
            Console.WriteLine("  --proxy <url>                  Route traffic through an HTTP proxy (disables cert validation)");
            Console.WriteLine("  --verbose, -v                  Show HTTP request/response details");
        }

        static async Task<int> RunCli(string[] args)
        {
            var positional = new List<string>();
            bool checkin = false;
            string proxyUrl = null;
            for (int i = 0; i < args.Length; i++)
            {
                var arg = args[i];
                if (arg.Equals("--verbose", StringComparison.OrdinalIgnoreCase) || arg == "-v")
                    Verbose = true;
                else if (arg.Equals("--checkin", StringComparison.OrdinalIgnoreCase))
                    checkin = true;
                else if (arg.Equals("--proxy", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                    proxyUrl = args[++i];
                else
                    positional.Add(arg);
            }

            var cmd = positional.Count > 0 ? positional[0].ToLower() : "help";

            if (cmd == "help" || cmd == "--help" || cmd == "-h")
            {
                ShowUsage();
                return 0;
            }

            if (cmd == "checkin")
                return await CmdCheckIn();

            if (cmd == "plugins")
                return CmdPlugins();

            if (cmd == "monitor")
                return CmdMonitor(positional);

            _rest = new IntuneRestClient(proxyUrl);

            if (Verbose) Console.WriteLine("[CLI] Authenticating via WAM broker...");
            if (!await _rest.AuthenticateWamAsync())
            {
                Console.Error.WriteLine("[CLI] WAM authentication failed.");
                return 1;
            }

            if (Verbose) Console.WriteLine("[CLI] Running WAM discovery...");
            if (!await _rest.DiscoverServicesWamAsync())
            {
                Console.Error.WriteLine("[CLI] WAM discovery failed.");
                return 1;
            }

            if (cmd == "diag")
            {
                _rest.DumpTokenClaims();
                return 0;
            }

            if (cmd == "states")
                return await CmdStates();

            if (cmd == "search")
            {
                var query = positional.Count > 1 ? positional[1] : null;
                if (string.IsNullOrEmpty(query))
                {
                    Console.Error.WriteLine("Usage: IMEClient.exe search <query>");
                    return 1;
                }
                return await CmdSearch(query);
            }

            if (cmd == "list" || cmd == "install" || cmd == "uninstall" || cmd == "details")
            {
                var apps = await FetchAppList();
                if (apps == null) return 1;

                if (cmd == "list")
                    return CmdList(apps);

                if (cmd == "details")
                {
                    var appArg = positional.Count > 1 ? positional[1] : null;
                    if (string.IsNullOrEmpty(appArg))
                    {
                        Console.Error.WriteLine("Usage: IMEClient.exe details <number|guid>");
                        return 1;
                    }
                    return await CmdDetails(apps, appArg);
                }

                return await CliWamAction(positional, apps, cmd, checkin);
            }

            Console.Error.WriteLine($"Unknown command: {cmd}");
            ShowUsage();
            return 1;
        }

        static async Task<List<JsonElement>> FetchAppList()
        {
            try
            {
                var json = await _rest.ListApplicationsRawAsync(top: 100);
                var doc = JsonDocument.Parse(json);
                JsonElement appArray;
                if (!doc.RootElement.TryGetProperty("value", out appArray)
                    || appArray.ValueKind != JsonValueKind.Array
                    || appArray.GetArrayLength() == 0)
                {
                    Console.WriteLine("No applications returned.");
                    if (Verbose) Console.WriteLine(json.Length > 2000 ? json.Substring(0, 2000) : json);
                    return null;
                }

                var apps = new List<JsonElement>();
                foreach (var item in appArray.EnumerateArray())
                    apps.Add(item);
                return apps;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"List failed: {ex.Message}");
                return null;
            }
        }

        static int CmdList(List<JsonElement> apps)
        {
            Console.WriteLine($"{apps.Count} application(s):");
            Console.WriteLine();
            Console.WriteLine("  {0,-3} {1,-38} {2,-35} {3,-20} {4}",
                "#", "AppId", "Name", "Publisher", "Channel");
            Console.WriteLine("  " + new string('-', 110));

            for (int i = 0; i < apps.Count; i++)
            {
                var item = apps[i];
                var appId = item.GetString("GuidKey") ?? "?";
                var name = item.GetString("Name") ?? "?";
                var pub = item.GetString("Publisher") ?? "";
                var chan = item.GetString("DistributionChannel") ?? "";

                if (name.Length > 33) name = name.Substring(0, 30) + "...";
                if (pub.Length > 18) pub = pub.Substring(0, 15) + "...";

                Console.WriteLine("  {0,-3} {1,-38} {2,-35} {3,-20} {4}",
                    i + 1, appId, name, pub, chan);
            }
            Console.WriteLine();
            return 0;
        }

        static async Task<int> CmdStates()
        {
            try
            {
                var json = await _rest.GetApplicationStatesRawAsync();
                var doc = JsonDocument.Parse(json);
                JsonElement arr;
                if (!doc.RootElement.TryGetProperty("value", out arr)
                    || arr.ValueKind != JsonValueKind.Array
                    || arr.GetArrayLength() == 0)
                {
                    Console.WriteLine("No states returned.");
                    return 0;
                }

                var items = new List<JsonElement>();
                foreach (var item in arr.EnumerateArray())
                    items.Add(item);

                Console.WriteLine($"{items.Count} app state(s):");
                Console.WriteLine();
                Console.WriteLine("  {0,-38} {1,-20} {2,-15} {3,-5} {4,-5}",
                    "AppId", "Status", "Approval", "Inst", "Uninst");
                Console.WriteLine("  " + new string('-', 90));

                foreach (var item in items)
                {
                    var raw = item.GetRawText();
                    var appId = item.GetString("ApplicationId") ?? "?";
                    var status = item.GetString("CombinedStatus") ?? "";
                    var approval = item.GetString("EffectiveApproval") ?? "";

                    var hasInstall = ExtractODataActionTarget(raw, "Install") != null;
                    var hasUninstall = ExtractODataActionTarget(raw, "Uninstall") != null;

                    Console.WriteLine("  {0,-38} {1,-20} {2,-15} {3,-5} {4,-5}",
                        appId, status, approval,
                        hasInstall ? "YES" : "-",
                        hasUninstall ? "YES" : "-");
                }
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"States failed: {ex.Message}");
                return 1;
            }
        }

        static async Task<int> CmdSearch(string query)
        {
            try
            {
                var json = await _rest.ListApplicationsRawAsync(top: 50, search: query);
                var doc = JsonDocument.Parse(json);
                JsonElement arr;
                if (!doc.RootElement.TryGetProperty("value", out arr)
                    || arr.ValueKind != JsonValueKind.Array
                    || arr.GetArrayLength() == 0)
                {
                    Console.WriteLine($"No results for '{query}'.");
                    return 0;
                }

                int i = 0;
                foreach (var item in arr.EnumerateArray())
                {
                    var name = item.GetString("Name") ?? "?";
                    var appId = item.GetString("GuidKey") ?? "?";
                    Console.WriteLine($"  {++i}. {name} ({appId})");
                }
                Console.WriteLine($"{i} result(s) for '{query}'.");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Search failed: {ex.Message}");
                return 1;
            }
        }

        static async Task<int> CmdDetails(List<JsonElement> apps, string appArg)
        {
            var selected = ResolveApp(apps, appArg);
            if (selected == null)
            {
                Console.Error.WriteLine($"Could not find app matching '{appArg}'.");
                return 1;
            }

            var app = selected.Value;
            var appName = app.GetString("Name") ?? "?";
            var appGuid = app.GetString("GuidKey") ?? "?";
            Console.WriteLine($"Name:      {appName}");
            Console.WriteLine($"AppId:     {appGuid}");
            Console.WriteLine($"Publisher: {app.GetString("Publisher") ?? ""}");
            Console.WriteLine($"Channel:   {app.GetString("DistributionChannel") ?? ""}");

            var stateJson = await FetchAppState(app.GetRawText(), appGuid);
            if (stateJson != null)
            {
                var stateDoc = JsonDocument.Parse(stateJson);
                Console.WriteLine($"Status:    {stateDoc.RootElement.GetString("CombinedStatus") ?? ""}");
                Console.WriteLine($"Extended:  {stateDoc.RootElement.GetString("ExtendedCombinedStatus") ?? ""}");

                var installTarget = ExtractODataActionTarget(stateJson, "Install");
                var uninstallTarget = ExtractODataActionTarget(stateJson, "Uninstall");
                var approvalTarget = ExtractODataActionTarget(stateJson, "RequestInstallWithApproval");

                if (installTarget != null) Console.WriteLine($"Install:   {installTarget}");
                if (uninstallTarget != null) Console.WriteLine($"Uninstall: {uninstallTarget}");
                if (approvalTarget != null) Console.WriteLine($"Approval:  {approvalTarget}");
                if (installTarget == null && uninstallTarget == null && approvalTarget == null)
                    Console.WriteLine("Actions:   (none available)");
            }
            else
            {
                Console.WriteLine("State:     (could not fetch)");
            }

            return 0;
        }

        static async Task<int> CliWamAction(List<string> positional, List<JsonElement> apps, string desiredAction, bool checkin)
        {
            var appArg = positional.Count > 1 ? positional[1] : null;

            if (string.IsNullOrEmpty(appArg))
            {
                Console.WriteLine($"{apps.Count} application(s):");
                for (int i = 0; i < apps.Count; i++)
                {
                    var name = apps[i].GetString("Name") ?? "?";
                    var appId = apps[i].GetString("GuidKey") ?? "?";
                    Console.WriteLine($"  {i + 1}. {name} ({appId})");
                }
                Console.WriteLine();
                Console.Write($"Enter app number to {desiredAction} (or q to quit): ");
                appArg = Console.ReadLine()?.Trim();
                if (string.IsNullOrEmpty(appArg) || appArg == "q") return 0;
            }

            var selected = ResolveApp(apps, appArg);
            if (selected == null)
            {
                Console.Error.WriteLine($"Could not find app matching '{appArg}'.");
                return 1;
            }

            var selectedApp = selected.Value;
            var appName = selectedApp.GetString("Name") ?? "?";
            var appGuid = selectedApp.GetString("GuidKey") ?? "?";
            Console.WriteLine($"Selected: {appName} ({appGuid})");

            string appStateJson = await FetchAppState(selectedApp.GetRawText(), appGuid);
            if (string.IsNullOrEmpty(appStateJson))
            {
                Console.Error.WriteLine("Could not fetch ApplicationState for this app.");
                return 1;
            }

            var stateDoc = JsonDocument.Parse(appStateJson);
            var status = stateDoc.RootElement.GetString("CombinedStatus") ?? "";
            var extStatus = stateDoc.RootElement.GetString("ExtendedCombinedStatus") ?? "";
            Console.WriteLine($"State: {status}  Extended: {extStatus}");

            var installTarget = ExtractODataActionTarget(appStateJson, "Install");
            var uninstallTarget = ExtractODataActionTarget(appStateJson, "Uninstall");
            var requestApprovalTarget = ExtractODataActionTarget(appStateJson, "RequestInstallWithApproval");
            var cancelApprovalTarget = ExtractODataActionTarget(appStateJson, "CancelApprovalRequest");

            if (Verbose)
            {
                Console.WriteLine($"Install target:    {installTarget ?? "(none)"}");
                Console.WriteLine($"Uninstall target:  {uninstallTarget ?? "(none)"}");
                if (requestApprovalTarget != null)
                    Console.WriteLine($"RequestApproval:   {requestApprovalTarget}");
            }

            var actions = new List<AppAction>();
            if (!string.IsNullOrEmpty(installTarget))
                actions.Add(new AppAction { Name = "Install", TargetUri = installTarget });
            if (!string.IsNullOrEmpty(uninstallTarget))
                actions.Add(new AppAction { Name = "Uninstall", TargetUri = uninstallTarget });
            if (!string.IsNullOrEmpty(requestApprovalTarget))
                actions.Add(new AppAction { Name = "RequestInstallWithApproval", TargetUri = requestApprovalTarget });
            if (!string.IsNullOrEmpty(cancelApprovalTarget))
                actions.Add(new AppAction { Name = "CancelApprovalRequest", TargetUri = cancelApprovalTarget });

            if (actions.Count == 0)
            {
                Console.Error.WriteLine("No action targets available for this app.");
                return 1;
            }

            AppAction action = default;
            bool found = false;
            foreach (var a in actions)
            {
                if (a.Name.IndexOf(desiredAction, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    action = a;
                    found = true;
                    break;
                }
            }

            if (!found)
            {
                Console.WriteLine($"No '{desiredAction}' action found. Available actions:");
                for (int i = 0; i < actions.Count; i++)
                    Console.WriteLine($"  {i + 1}. {actions[i].Name}");
                Console.Write("Action number (or q to quit): ");
                var actionChoice = Console.ReadLine()?.Trim();
                if (string.IsNullOrEmpty(actionChoice) || actionChoice == "q") return 0;

                int actionNum;
                if (!int.TryParse(actionChoice, out actionNum) || actionNum < 1 || actionNum > actions.Count)
                {
                    Console.Error.WriteLine("Invalid selection.");
                    return 1;
                }
                action = actions[actionNum - 1];
            }

            Console.WriteLine($"Executing: {action.Name}");
            if (Verbose) Console.WriteLine($"Target: {action.TargetUri}");

            var userOid = _rest.GetUserOidFromToken();
            var postBody = !string.IsNullOrEmpty(userOid)
                ? JsonSerializer.Serialize(new { UserId = userOid })
                : "";

            var (succeeded, statusCode, responseBody) = await _rest.PostActionAsync(action.TargetUri, postBody);
            if (!succeeded)
            {
                Console.Error.WriteLine($"{action.Name} failed with HTTP {statusCode}.");
                return 1;
            }

            Console.WriteLine($"{action.Name} succeeded!");

            if (checkin)
                await TriggerCheckIn();

            return 0;
        }

        static int CmdPlugins()
        {
            var plugins = ListPlugins();
            if (plugins.Count == 0)
            {
                Console.WriteLine("No plugins found.");
                return 0;
            }
            Console.WriteLine($"{plugins.Count} plugin(s):");
            foreach (var p in plugins)
                Console.WriteLine($"  {p}");
            return 0;
        }

        static int CmdMonitor(List<string> positional)
        {
            if (positional.Count < 2)
            {
                Console.Error.WriteLine("Usage: IMEClient.exe monitor <plugin>[,plugin,...] [args...]");
                Console.Error.WriteLine();
                var available = ListPlugins();
                if (available.Count > 0)
                {
                    Console.Error.WriteLine("Available plugins:");
                    foreach (var p in available)
                        Console.Error.WriteLine($"  {p}");
                }
                return 1;
            }

            // Resolve all plugin types up front
            var allTypes = AppDomain.CurrentDomain.GetAssemblies().SelectMany(s => s.GetTypes());
            var pluginTypes = allTypes.Where(p => typeof(InstallerPlugin).IsAssignableFrom(p) && !p.IsAbstract).ToList();

            // "all" keyword enables every discovered plugin
            // Otherwise plugin names can be comma-separated and/or space-separated.
            // Anything that doesn't resolve as a plugin name is treated as a plugin arg.
            var monitor = new PluginMonitor();
            var pluginArgs = new List<string>();

            if (positional[1].Equals("all", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var t in pluginTypes)
                    monitor.Add((InstallerPlugin)Activator.CreateInstance(t, new object[] { new string[0] }));
                for (int i = 2; i < positional.Count; i++)
                    pluginArgs.Add(positional[i]);
            }
            else
            {
                bool doneNames = false;
                for (int i = 1; i < positional.Count; i++)
                {
                    if (doneNames)
                    {
                        pluginArgs.Add(positional[i]);
                        continue;
                    }

                    // Try splitting on comma for "NSIS,DXSetup" style
                    var names = positional[i].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    bool allResolved = true;
                    var resolved = new List<Type>();

                    foreach (var name in names)
                    {
                        var match = ResolvePluginType(pluginTypes, name);
                        if (match == null)
                        {
                            allResolved = false;
                            break;
                        }
                        resolved.Add(match);
                    }

                    if (allResolved && resolved.Count > 0)
                    {
                        foreach (var t in resolved)
                            monitor.Add((InstallerPlugin)Activator.CreateInstance(t, new object[] { new string[0] }));
                    }
                    else
                    {
                        doneNames = true;
                        pluginArgs.Add(positional[i]);
                    }
                }
            }

            if (monitor.PluginCount == 0)
            {
                Console.Error.WriteLine($"No plugins could be resolved.");
                var available = ListPlugins();
                if (available.Count > 0)
                {
                    Console.Error.WriteLine("Available plugins:");
                    foreach (var p in available)
                        Console.Error.WriteLine($"  {p}");
                }
                return 1;
            }

            Console.WriteLine("Press Ctrl+C to stop.");

            using (var cts = new CancellationTokenSource())
            {
                Console.CancelKeyPress += (s, e) =>
                {
                    e.Cancel = true;
                    cts.Cancel();
                };

                try
                {
                    monitor.Run(cts.Token);
                }
                catch (OperationCanceledException)
                {
                    // normal shutdown
                }
            }

            Console.WriteLine("Monitor stopped.");
            return 0;
        }

        static Type ResolvePluginType(List<Type> pluginTypes, string name)
        {
            foreach (var t in pluginTypes)
            {
                if (t.Name.Equals(name, StringComparison.OrdinalIgnoreCase)
                    || t.Name.Equals(name + "Plugin", StringComparison.OrdinalIgnoreCase))
                    return t;
            }
            return null;
        }

        struct AppAction
        {
            public string Name;
            public string TargetUri;
        }

        static async Task<int> CmdCheckIn()
        {
            await TriggerCheckIn();
            return 0;
        }

        static async Task TriggerCheckIn()
        {
            Console.WriteLine("Connecting to IME named pipe for check-in...");
            try
            {
                ConnectPipe(DefaultPipeEndpoint);
                var sid = Guid.NewGuid();
                if (Verbose) Console.WriteLine($"Triggering check-in (session={sid})...");
                await _pipe.CheckInAsync(sid);
                Console.WriteLine("Check-in sent. IME service will sync with Intune.");
                _channel.Close();
            }
            catch (EndpointNotFoundException)
            {
                Console.Error.WriteLine("IME service not running.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Check-in failed: {ex.Message}");
            }
        }

        static JsonElement? ResolveApp(List<JsonElement> apps, string appArg)
        {
            int appNum;
            if (int.TryParse(appArg, out appNum) && appNum >= 1 && appNum <= apps.Count)
                return apps[appNum - 1];

            foreach (var item in apps)
            {
                var gk = item.GetString("GuidKey") ?? "";
                if (gk.Equals(appArg, StringComparison.OrdinalIgnoreCase))
                    return item;
            }
            return null;
        }

        static async Task<string> FetchAppState(string appEntityJson, string appGuid)
        {
            var appDoc = JsonDocument.Parse(appEntityJson);
            var navLink = appDoc.RootElement.GetString("ApplicationState@odata.navigationLinkUrl");
            if (string.IsNullOrEmpty(navLink))
                return null;

            if (!navLink.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                navLink = _rest.IWServiceUrl + "/" + navLink.TrimStart('/');

            if (Verbose) Console.WriteLine($"ApplicationState nav link: {navLink}");

            var stateRawJson = await _rest.GetApplicationStateWithActionsAsync(navLink);
            if (string.IsNullOrEmpty(stateRawJson))
                return null;

            var doc = JsonDocument.Parse(stateRawJson);
            JsonElement arr;
            if (!doc.RootElement.TryGetProperty("value", out arr) || arr.ValueKind != JsonValueKind.Array)
                return null;

            foreach (var item in arr.EnumerateArray())
            {
                var stateAppId = item.GetString("ApplicationId") ?? "";
                if (stateAppId.Equals(appGuid, StringComparison.OrdinalIgnoreCase))
                    return item.GetRawText();
            }

            return null;
        }

        /// <summary>
        /// Extracts an OData action target URL from a raw JSON state string.
        /// In fullmetadata format, actions appear as: "#Install":{"target":"https://..."}
        /// We use string search here because System.Text.Json can't enumerate properties
        /// with # prefixes easily across the various naming patterns the server uses.
        /// </summary>
        static string ExtractODataActionTarget(string json, string actionName)
        {
            string[] patterns = new[]
            {
                $"\"#{actionName}\"",
                $"\"{actionName}\"",
                $"\"#Microsoft.Services.SystemCenter.IWService.Common.{actionName}\""
            };

            foreach (var pattern in patterns)
            {
                var idx = json.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
                if (idx < 0) continue;

                var searchStart = idx + pattern.Length;
                var searchEnd = Math.Min(json.Length, searchStart + 300);
                var targetIdx = json.IndexOf("\"target\"", searchStart, searchEnd - searchStart, StringComparison.OrdinalIgnoreCase);
                if (targetIdx < 0) continue;

                var targetVal = ExtractJsonStringAfterKey(json, targetIdx);
                if (!string.IsNullOrEmpty(targetVal))
                    return targetVal;
            }

            return null;
        }

        static string ExtractJsonStringAfterKey(string json, int keyPos)
        {
            var colonIdx = json.IndexOf(':', keyPos);
            if (colonIdx < 0) return null;

            var openQuote = json.IndexOf('"', colonIdx + 1);
            if (openQuote < 0 || openQuote > colonIdx + 10) return null;

            var closeQuote = openQuote + 1;
            while (closeQuote < json.Length)
            {
                if (json[closeQuote] == '"' && json[closeQuote - 1] != '\\')
                    break;
                closeQuote++;
            }
            if (closeQuote >= json.Length) return null;

            return json.Substring(openQuote + 1, closeQuote - openQuote - 1);
        }
    }
}