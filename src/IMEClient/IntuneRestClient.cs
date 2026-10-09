using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace IMEClient
{
    class IntuneRestClient : IDisposable
    {
        public const string IntuneResourceId = "0000000a-0000-0000-c000-000000000000";
        public const string IntuneMAMResourceId = "d4ebce55-015a-49b5-a083-c84d1797ae8c";
        public const string CompanyPortalClientId = "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223";

        const string AadAuthority = "https://login.microsoftonline.com/common";

        readonly HttpClient _http;
        string _accessToken;
        string _iwServiceUrl;
        string _enrollmentToken;
        string _negotiatedApiVersion;
        string _intuneDeviceId;

        WamTokenProvider _wam;

        public string IWServiceUrl => _iwServiceUrl;

        static bool V => Program.Verbose;

        static readonly JwtSecurityTokenHandler _jwtHandler = new JwtSecurityTokenHandler();

        public string GetUserOidFromToken()
        {
            var jwt = ReadToken(_accessToken);
            return jwt?.Payload?.TryGetValue("oid", out var oid) == true ? oid?.ToString() ?? "" : "";
        }

        public IntuneRestClient(string proxyUrl = null)
        {
            if (!string.IsNullOrEmpty(proxyUrl))
            {
                var handler = new HttpClientHandler
                {
                    Proxy = new WebProxy(proxyUrl),
                    UseProxy = true,
                    ServerCertificateCustomValidationCallback = (_, _, _, _) => true
                };
                _http = new HttpClient(handler);
                if (V) Console.WriteLine($"[HTTP] Using proxy: {proxyUrl} (certificate validation disabled)");
            }
            else
            {
                _http = new HttpClient();
            }
            _http.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));
        }

        public async Task<bool> AuthenticateWamAsync()
        {
            if (V) Console.WriteLine("[WAM] Initializing WAM token provider...");

            try
            {
                _wam = new WamTokenProvider(CompanyPortalClientId, AadAuthority);

                if (V) Console.WriteLine("[WAM] Acquiring token silently via OS account...");
                var result = await _wam.GetTokenSilentlyAsync(IntuneResourceId + "/.default");

                _accessToken = result.AccessToken;
                Console.WriteLine($"[WAM] Authenticated as: {result.Username ?? "(unknown)"}");

                if (V)
                {
                    var jwt = ReadToken(_accessToken);
                    if (jwt != null)
                    {
                        Console.WriteLine($"[WAM] deviceid: {GetClaim(jwt, "deviceid") ?? "(none)"}");
                        Console.WriteLine($"[WAM] aud: {GetClaim(jwt, "aud")}");
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[WAM] Silent auth failed: {ex.GetType().Name}: {ex.Message}");
                if (ex.InnerException != null)
                    Console.Error.WriteLine($"  Inner: {ex.InnerException.Message}");
                return false;
            }
        }

        async Task<string> GetWamTokenForResourceAsync(string resource)
        {
            var result = await _wam.GetTokenSilentlyAsync(resource + "/.default");
            return result.AccessToken;
        }

        public async Task<bool> DiscoverServicesWamAsync()
        {
            if (V) Console.WriteLine("[DISCOVER] Getting Graph token...");
            var graphToken = await GetWamTokenForResourceAsync("https://graph.microsoft.com");

            if (V) Console.WriteLine("[DISCOVER] Querying Graph for Intune service endpoints...");
            var epUrl = $"https://graph.microsoft.com/v1.0/myorganization/servicePrincipals/appId={IntuneResourceId}/endpoints";
            var epReq = new HttpRequestMessage(HttpMethod.Get, epUrl);
            epReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", graphToken);
            var epResp = await _http.SendAsync(epReq);
            var epJson = await epResp.Content.ReadAsStringAsync();

            if (!epResp.IsSuccessStatusCode)
            {
                Console.Error.WriteLine($"[DISCOVER] Graph query failed ({epResp.StatusCode}): {epJson}");
                return false;
            }

            var epDoc = JsonDocument.Parse(epJson);
            _iwServiceUrl = FindGraphEndpoint(epDoc, "IWService");

            if (string.IsNullOrEmpty(_iwServiceUrl))
            {
                Console.Error.WriteLine("[DISCOVER] Could not find IWService endpoint.");
                return false;
            }

            var tokenRenewalUrl = FindGraphEndpoint(epDoc, "TokenRenewalService");

            if (V)
            {
                Console.WriteLine($"[DISCOVER] IWService:           {_iwServiceUrl}");
                if (!string.IsNullOrEmpty(tokenRenewalUrl))
                    Console.WriteLine($"[DISCOVER] TokenRenewalService: {tokenRenewalUrl}");
            }

            if (string.IsNullOrEmpty(tokenRenewalUrl))
            {
                Console.Error.WriteLine("[DISCOVER] Could not find TokenRenewalService endpoint.");
                return false;
            }

            if (V) Console.WriteLine("[DISCOVER] Getting enrollment token via TokenRenewalService...");
            var mamToken = await GetWamTokenForResourceAsync(IntuneMAMResourceId);

            var renewUrl = $"{tokenRenewalUrl}?api-version=1.0";
            var renewReq = new HttpRequestMessage(HttpMethod.Get, renewUrl);
            renewReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", mamToken);
            var renewResp = await _http.SendAsync(renewReq);
            var renewJson = await renewResp.Content.ReadAsStringAsync();

            if (!renewResp.IsSuccessStatusCode)
            {
                Console.Error.WriteLine($"[DISCOVER] Token renewal failed ({renewResp.StatusCode})");
                return false;
            }

            var renewDoc = JsonDocument.Parse(renewJson);
            _enrollmentToken = renewDoc.RootElement.GetPath("Result", "Token");

            if (string.IsNullOrEmpty(_enrollmentToken))
            {
                Console.Error.WriteLine("[DISCOVER] TokenRenewalService returned no token.");
                return false;
            }

            if (V)
            {
                Console.WriteLine("[DISCOVER] Got enrollment token.");
                var etJwt = ReadToken(_enrollmentToken);
                if (etJwt != null)
                {
                    Console.WriteLine($"  MamClaim: {GetClaim(etJwt, "MamClaim")}");
                    Console.WriteLine($"  AzureADDeviceId: {GetClaim(etJwt, "AzureADDeviceId")}");
                    Console.WriteLine($"  License: {GetClaim(etJwt, "License")}");
                }
            }

            if (V) Console.WriteLine("[DISCOVER] Negotiating API version...");
            await NegotiateApiVersionAsync();

            if (V) Console.WriteLine("[DISCOVER] Discovering Intune Managed Device ID from MDM cert...");
            _intuneDeviceId = DiscoverIntuneDeviceIdFromCert();

            if (!string.IsNullOrEmpty(_intuneDeviceId))
            {
                if (V) Console.WriteLine($"[DISCOVER] Intune Device ID: {_intuneDeviceId}");
            }
            else
            {
                Console.Error.WriteLine("[DISCOVER] WARNING: Could not find MDM cert. App listing may return empty.");
            }

            return true;
        }

        static string FindGraphEndpoint(JsonDocument doc, string providerName)
        {
            if (!doc.RootElement.TryGetProperty("value", out var arr)) return null;
            foreach (var ep in arr.EnumerateArray())
            {
                var pn = ep.GetString("providerName");
                if (string.Equals(pn, providerName, StringComparison.OrdinalIgnoreCase))
                    return ep.GetString("uri");
            }
            return null;
        }

        static readonly string[] ClientSupportedVersions = new[]
        {
            "1.1","2.0","2.1","3.0","4.0","6.0","7.0","8.0","8.1","8.2",
            "9.0","9.1","9.2","9.3","9.4","9.5","9.6","9.7","9.8","9.9",
            "9.10","9.11","9.12","9.13","9.14","9.15","9.16","9.17","9.18",
            "9.19","9.20","9.21","9.22","9.23","9.24","9.25","9.26","9.27",
            "9.28","9.29","9.30","9.31","9.32","9.33","9.34",
            "10.3","10.4","10.5","10.6","10.7","10.8","10.9","10.10","10.11",
            "10.12","10.13","10.14","10.15","10.16","10.17",
            "11.1","11.2","11.3","11.4","11.5",
            "12.1","12.2","12.3","12.4","12.5","12.6","12.7","12.8","12.9",
            "13.2","13.3","13.4","13.5","13.6",
            "14.1","14.2","14.3","14.4","14.5","14.6","14.7","14.8","14.9",
            "14.10","14.11","14.12",
            "15.0","15.1","15.2",
            "16.3","16.4","16.5","16.6","16.7","16.8",
            "17.0",
            "18.2","18.3","18.4","18.5","18.6","18.7","18.8","18.9","18.10"
        };

        async Task NegotiateApiVersionAsync()
        {
            var req = new HttpRequestMessage(HttpMethod.Options, _iwServiceUrl);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _enrollmentToken);
            req.Headers.TryAddWithoutValidation("Accept", "application/json; odata=fullmetadata");
            req.Headers.TryAddWithoutValidation("Accept-Language", System.Globalization.CultureInfo.CurrentCulture.Name);

            var resp = await _http.SendAsync(req);
            if (V) Console.WriteLine($"[VERSION] OPTIONS response: {(int)resp.StatusCode}");

            string versionsHeader = null;
            IEnumerable<string> values;
            if (resp.Headers.TryGetValues("api-supported-versions", out values))
                versionsHeader = string.Join(",", values);

            if (string.IsNullOrEmpty(versionsHeader))
            {
                _negotiatedApiVersion = "9.0";
                if (V) Console.WriteLine($"[VERSION] No api-supported-versions header, defaulting to {_negotiatedApiVersion}");
                return;
            }

            if (V) Console.WriteLine($"[VERSION] Server supports: {versionsHeader}");

            var serverVersions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var v in versionsHeader.Split(','))
            {
                var trimmed = v.Trim();
                if (!string.IsNullOrEmpty(trimmed))
                    serverVersions.Add(trimmed);
            }

            string best = null;
            Version bestParsed = null;
            foreach (var cv in ClientSupportedVersions)
            {
                if (serverVersions.Contains(cv))
                {
                    Version parsed;
                    if (Version.TryParse(cv, out parsed))
                    {
                        if (bestParsed == null || parsed > bestParsed)
                        {
                            best = cv;
                            bestParsed = parsed;
                        }
                    }
                }
            }

            _negotiatedApiVersion = best ?? "9.0";
            if (V) Console.WriteLine($"[VERSION] Negotiated api-version={_negotiatedApiVersion}");
        }

        public async Task<string> ListApplicationsRawAsync(int top = 50, int skip = 0, string search = null)
        {
            var url = $"{_iwServiceUrl}/Applications?$top={top}&$skip={skip}";
            if (!string.IsNullOrEmpty(search))
                url += $"&searchString={Uri.EscapeDataString(search)}";

            return await GetAsync(url, includeDeviceId: true);
        }

        public async Task<string> GetApplicationStatesRawAsync()
        {
            return await GetAsync($"{_iwServiceUrl}/ApplicationState", includeDeviceId: true);
        }

        /// <summary>
        /// Gets ApplicationState via a per-app navigation link with DeviceId filter and fullmetadata,
        /// so OData action targets (#Install, #Uninstall) are included in the response.
        /// </summary>
        public async Task<string> GetApplicationStateWithActionsAsync(string statesLink)
        {
            var url = statesLink;
            if (!string.IsNullOrEmpty(_intuneDeviceId))
                url += (url.Contains("?") ? "&" : "?") + $"$filter=DeviceId%20eq%20guid'{_intuneDeviceId}'";

            url = AppendServiceParams(url, includeDeviceId: true);
            var req = BuildRequest(HttpMethod.Get, url, _enrollmentToken);

            if (V) Console.WriteLine($"[HTTP] GET {url}");
            var resp = await _http.SendAsync(req);
            var body = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode)
            {
                if (V) Console.Error.WriteLine($"[HTTP] {(int)resp.StatusCode}: {(body.Length > 300 ? body.Substring(0, 300) : body)}");
                return null;
            }

            return body;
        }

        /// <summary>
        /// POSTs to an OData action target URI (Install/Uninstall).
        /// Uses Content-Type: application/json, no Accept: odata=fullmetadata on POST.
        /// </summary>
        public async Task<(bool success, int statusCode, string body)> PostActionAsync(string actionTargetUri, string jsonBody = "")
        {
            var url = AppendServiceParams(actionTargetUri, includeDeviceId: true);

            var req = new HttpRequestMessage(HttpMethod.Post, url);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _enrollmentToken);
            req.Headers.TryAddWithoutValidation("Accept-Language", System.Globalization.CultureInfo.CurrentCulture.Name);
            req.Headers.TryAddWithoutValidation("client-request-id", Guid.NewGuid().ToString());
            req.Content = new StringContent(jsonBody ?? "", Encoding.UTF8, "application/json");

            if (V)
            {
                Console.WriteLine($"[HTTP] POST {url}");
                Console.WriteLine($"[HTTP] Body: {(string.IsNullOrEmpty(jsonBody) ? "(empty)" : jsonBody)}");
            }

            var resp = await _http.SendAsync(req);
            var body = await resp.Content.ReadAsStringAsync();

            if (V)
            {
                Console.WriteLine($"[HTTP] Response: {(int)resp.StatusCode} {resp.StatusCode}");
                if (!string.IsNullOrEmpty(body) && body.Length > 2)
                    Console.WriteLine($"[HTTP] {(body.Length > 500 ? body.Substring(0, 500) : body)}");
            }

            return (resp.IsSuccessStatusCode, (int)resp.StatusCode, body);
        }

        string BuildQueryParams(bool includeDeviceId = false)
        {
            var apiVer = _negotiatedApiVersion ?? "9.0";

            var parts = new List<string>
            {
                $"api-version={apiVer}",
                "ssp=WindowsSSP",
                "ssp-version=11.2.1753.0",
                "os=Windows",
                "os-version=10.0.26100.0",
                "os-sub=None",
                $"arch={(Environment.Is64BitOperatingSystem ? "x64" : "x86")}",
                "mgmt-agent=Mdm",
            };

            if (includeDeviceId && !string.IsNullOrEmpty(_intuneDeviceId))
                parts.Add($"device-id={_intuneDeviceId}");

            return string.Join("&", parts);
        }

        string DiscoverIntuneDeviceIdFromCert()
        {
            try
            {
                using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
                {
                    store.Open(OpenFlags.ReadOnly);
                    foreach (var cert in store.Certificates)
                    {
                        if (cert.Issuer.IndexOf("Microsoft Intune MDM Device CA", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
                            Guid parsed;
                            if (!string.IsNullOrEmpty(cn) && Guid.TryParse(cn, out parsed))
                                return parsed.ToString();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (V) Console.Error.WriteLine($"[WARN] Could not read cert store: {ex.Message}");
            }
            return null;
        }

        string AppendServiceParams(string url, bool includeDeviceId = false)
        {
            return url + (url.Contains("?") ? "&" : "?") + BuildQueryParams(includeDeviceId);
        }

        HttpRequestMessage BuildRequest(HttpMethod method, string url, string token)
        {
            var req = new HttpRequestMessage(method, url);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            req.Headers.TryAddWithoutValidation("Accept", "application/json; odata=fullmetadata");
            req.Headers.TryAddWithoutValidation("Accept-Language", System.Globalization.CultureInfo.CurrentCulture.Name);
            req.Headers.TryAddWithoutValidation("client-request-id", Guid.NewGuid().ToString());
            return req;
        }

        async Task<string> GetAsync(string url, bool includeDeviceId = false)
        {
            url = AppendServiceParams(url, includeDeviceId);
            var req = BuildRequest(HttpMethod.Get, url, _enrollmentToken);

            if (V) Console.WriteLine($"[HTTP] GET {url}");

            var resp = await _http.SendAsync(req);
            var body = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode)
                throw new Exception($"HTTP {(int)resp.StatusCode}: {body}");

            return body;
        }

        static JwtSecurityToken ReadToken(string token)
        {
            if (string.IsNullOrEmpty(token)) return null;
            try { return _jwtHandler.ReadJwtToken(token); }
            catch { return null; }
        }

        static string GetClaim(JwtSecurityToken jwt, string type)
        {
            if (jwt == null) return null;
            if (jwt.Payload.TryGetValue(type, out var val) && val != null)
                return val.ToString();
            return null;
        }

        public void DumpTokenClaims()
        {
            Console.WriteLine("=== Token Claims ===");
            DumpToken("Access Token", _accessToken);
            if (!string.IsNullOrEmpty(_enrollmentToken))
                DumpToken("Enrollment Token", _enrollmentToken);
        }

        static void DumpToken(string label, string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                Console.WriteLine($"  {label}: (none)");
                return;
            }

            var jwt = ReadToken(token);
            if (jwt == null)
            {
                Console.WriteLine($"  {label}: (could not decode)");
                return;
            }

            Console.WriteLine($"  {label}:");
            foreach (var key in new[] { "aud", "iss", "appid", "upn", "unique_name", "preferred_username",
                                         "tid", "oid", "scp", "roles", "wids", "deviceid", "exp", "iat" })
            {
                var val = GetClaim(jwt, key);
                if (val != null)
                    Console.WriteLine($"    {key}: {val}");
            }
            Console.WriteLine();
        }

        public void Dispose()
        {
            _http?.Dispose();
        }
    }

    static class JsonElementExtensions
    {
        public static string GetString(this JsonDocument doc, string key)
        {
            return doc.RootElement.GetString(key);
        }

        public static string GetString(this JsonElement el, string key)
        {
            if (el.TryGetProperty(key, out var prop))
            {
                if (prop.ValueKind == JsonValueKind.String)
                    return prop.GetString();
                if (prop.ValueKind == JsonValueKind.Number)
                    return prop.GetRawText();
                if (prop.ValueKind == JsonValueKind.True || prop.ValueKind == JsonValueKind.False)
                    return prop.GetBoolean().ToString();
            }
            return null;
        }

        public static string GetPath(this JsonElement el, params string[] keys)
        {
            var current = el;
            for (int i = 0; i < keys.Length - 1; i++)
            {
                if (!current.TryGetProperty(keys[i], out current))
                    return null;
            }
            return current.GetString(keys[keys.Length - 1]);
        }
    }
}
