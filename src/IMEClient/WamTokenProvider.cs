using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace IMEClient
{
    class WamException : Exception
    {
        public WamException(string message) : base(message) { }
    }

    class WamToken
    {
        public string AccessToken;
        public string Username;
    }

    // Gets tokens for the default OS account from the AAD WAM plugin through WinRT COM interop.
    class WamTokenProvider
    {
        const string AadProviderId = "https://login.microsoft.com";
        const string AadProviderAuthority = "organizations";
        const string ManagerClass = "Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager";
        const string RequestClass = "Windows.Security.Authentication.Web.Core.WebTokenRequest";

        readonly string _clientId;
        readonly string _authority;
        readonly IWebAuthenticationCoreManagerStatics _manager;
        readonly IWebTokenRequestFactory _requestFactory;
        IWebAccountProvider _provider;

        static bool V => Program.Verbose;

        public WamTokenProvider(string clientId, string authority)
        {
            _clientId = clientId;
            _authority = authority;
            _manager = GetActivationFactory<IWebAuthenticationCoreManagerStatics>(ManagerClass);
            _requestFactory = GetActivationFactory<IWebTokenRequestFactory>(RequestClass);
        }

        public async Task<WamToken> GetTokenSilentlyAsync(string scope)
        {
            if (_provider == null)
            {
                var findOp = _manager.FindAccountProviderWithAuthorityAsync(AadProviderId, AadProviderAuthority);
                await WaitAsync(findOp);
                _provider = findOp.GetResults() ?? throw new WamException("AAD account provider not found.");
                if (V) Console.WriteLine($"[WAM] Account provider: {_provider.DisplayName} ({_provider.Id})");
            }

            var request = _requestFactory.Create(_provider, scope + " openid offline_access profile", _clientId);
            var properties = request.Properties;
            properties.Insert("wam_compat", "2.0");
            properties.Insert("authority", _authority);
            properties.Insert("redirect_uri", $"ms-appx-web://Microsoft.AAD.BrokerPlugin/{_clientId}");
            properties.Insert("correlationId", Guid.NewGuid().ToString());

            var tokenOp = _manager.GetTokenSilentlyAsync(request);
            await WaitAsync(tokenOp);
            var result = tokenOp.GetResults();

            var status = (WebTokenRequestStatus)result.ResponseStatus;
            if (status != WebTokenRequestStatus.Success)
            {
                var error = result.ResponseError;
                var detail = error == null ? "" : $" (0x{error.ErrorCode:X8}: {error.ErrorMessage})";
                throw new WamException($"Token request for '{scope}' returned {status}{detail}");
            }

            var response = result.ResponseData.GetAt(0);
            return new WamToken
            {
                AccessToken = response.Token,
                Username = response.WebAccount?.UserName,
            };
        }

        static async Task WaitAsync(object operation)
        {
            var info = (IAsyncInfo)operation;
            while (true)
            {
                switch ((AsyncStatus)info.Status)
                {
                    case AsyncStatus.Started:
                        await Task.Delay(20);
                        break;
                    case AsyncStatus.Completed:
                        return;
                    case AsyncStatus.Error:
                        Marshal.ThrowExceptionForHR(info.ErrorCode);
                        throw new WamException($"WinRT operation failed with 0x{info.ErrorCode:X8}");
                    default:
                        throw new OperationCanceledException();
                }
            }
        }

        static T GetActivationFactory<T>(string className)
        {
            var iid = typeof(T).GUID;
            RoGetActivationFactory(className, ref iid, out var factory);
            return (T)factory;
        }

        [DllImport("combase.dll", PreserveSig = false)]
        static extern void RoGetActivationFactory(
            [MarshalAs(UnmanagedType.HString)] string activatableClassId,
            [In] ref Guid iid,
            [MarshalAs(UnmanagedType.IInspectable)] out object factory);

        enum AsyncStatus { Started, Completed, Canceled, Error }

        enum WebTokenRequestStatus
        {
            Success,
            UserCancel,
            AccountSwitch,
            UserInteractionRequired,
            AccountProviderNotAvailable,
            ProviderError,
        }

        // Interface IDs and vtable order come from the Windows SDK winrt headers. Unused slots are placeholders.

        [ComImport, Guid("00000036-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIInspectable)]
        interface IAsyncInfo
        {
            uint Id { get; }
            int Status { get; }
            int ErrorCode { get; }
            void Cancel();
            void Close();
        }

        [ComImport, Guid("6aca7c92-a581-4479-9c10-752eff44fd34"), InterfaceType(ComInterfaceType.InterfaceIsIInspectable)]
        interface IWebAuthenticationCoreManagerStatics
        {
            IAsyncOperationWebTokenRequestResult GetTokenSilentlyAsync(IWebTokenRequest request);
            void GetTokenSilentlyWithWebAccountAsync();
            void RequestTokenAsync();
            void RequestTokenWithWebAccountAsync();
            void FindAccountAsync();
            void FindAccountProviderAsync();
            IAsyncOperationWebAccountProvider FindAccountProviderWithAuthorityAsync(
                [MarshalAs(UnmanagedType.HString)] string webAccountProviderId,
                [MarshalAs(UnmanagedType.HString)] string authority);
        }

        [ComImport, Guid("6cf2141c-0ff0-4c67-b84f-99ddbe4a72c9"), InterfaceType(ComInterfaceType.InterfaceIsIInspectable)]
        interface IWebTokenRequestFactory
        {
            IWebTokenRequest Create(
                IWebAccountProvider provider,
                [MarshalAs(UnmanagedType.HString)] string scope,
                [MarshalAs(UnmanagedType.HString)] string clientId);
        }

        [ComImport, Guid("b77b4d68-adcb-4673-b364-0cf7b35caf97"), InterfaceType(ComInterfaceType.InterfaceIsIInspectable)]
        interface IWebTokenRequest
        {
            IWebAccountProvider WebAccountProvider { get; }
            string Scope { [return: MarshalAs(UnmanagedType.HString)] get; }
            string ClientId { [return: MarshalAs(UnmanagedType.HString)] get; }
            int PromptType { get; }
            IMapStringString Properties { get; }
        }

        [ComImport, Guid("f6d1f700-49c2-52ae-8154-826f9908773c"), InterfaceType(ComInterfaceType.InterfaceIsIInspectable)]
        interface IMapStringString
        {
            void Lookup();
            uint Size { get; }
            void HasKey();
            void GetView();
            bool Insert([MarshalAs(UnmanagedType.HString)] string key, [MarshalAs(UnmanagedType.HString)] string value);
        }

        [ComImport, Guid("29dcc8c3-7ab9-4a7c-a336-b942f9dbf7c7"), InterfaceType(ComInterfaceType.InterfaceIsIInspectable)]
        interface IWebAccountProvider
        {
            string Id { [return: MarshalAs(UnmanagedType.HString)] get; }
            string DisplayName { [return: MarshalAs(UnmanagedType.HString)] get; }
        }

        [ComImport, Guid("88c66009-12f7-58e2-8dbe-6efc620c85ba"), InterfaceType(ComInterfaceType.InterfaceIsIInspectable)]
        interface IAsyncOperationWebAccountProvider
        {
            void put_Completed();
            void get_Completed();
            IWebAccountProvider GetResults();
        }

        [ComImport, Guid("0a815852-7c44-5674-b3d2-fa2e4c1e46c9"), InterfaceType(ComInterfaceType.InterfaceIsIInspectable)]
        interface IAsyncOperationWebTokenRequestResult
        {
            void put_Completed();
            void get_Completed();
            IWebTokenRequestResult GetResults();
        }

        [ComImport, Guid("c12a8305-d1f8-4483-8d54-38fe292784ff"), InterfaceType(ComInterfaceType.InterfaceIsIInspectable)]
        interface IWebTokenRequestResult
        {
            IVectorViewWebTokenResponse ResponseData { get; }
            int ResponseStatus { get; }
            IWebProviderError ResponseError { get; }
        }

        [ComImport, Guid("199e065c-8195-55da-9c10-8aeaf9ac1062"), InterfaceType(ComInterfaceType.InterfaceIsIInspectable)]
        interface IVectorViewWebTokenResponse
        {
            IWebTokenResponse GetAt(uint index);
            uint Size { get; }
        }

        [ComImport, Guid("67a7c5ca-83f6-44c6-a3b1-0eb69e41fa8a"), InterfaceType(ComInterfaceType.InterfaceIsIInspectable)]
        interface IWebTokenResponse
        {
            string Token { [return: MarshalAs(UnmanagedType.HString)] get; }
            IWebProviderError ProviderError { get; }
            IWebAccount WebAccount { get; }
        }

        [ComImport, Guid("db191bb1-50c5-4809-8dca-09c99410245c"), InterfaceType(ComInterfaceType.InterfaceIsIInspectable)]
        interface IWebProviderError
        {
            uint ErrorCode { get; }
            string ErrorMessage { [return: MarshalAs(UnmanagedType.HString)] get; }
        }

        [ComImport, Guid("69473eb2-8031-49be-80bb-96cb46d99aba"), InterfaceType(ComInterfaceType.InterfaceIsIInspectable)]
        interface IWebAccount
        {
            IWebAccountProvider WebAccountProvider { get; }
            string UserName { [return: MarshalAs(UnmanagedType.HString)] get; }
        }
    }
}
