using System;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.Threading.Tasks;

namespace IMEClient
{
    // The server's CLR namespace. WCF derives XML namespaces from this
    static class Ns
    {
        public const string Dc = "http://schemas.datacontract.org/2004/07/"
            + "Microsoft.Management.Clients.IntuneManagementExtension.StatusServiceLibrary";
    }

    // WCF Service Contract
    [ServiceContract(
        SessionMode = SessionMode.Required,
        CallbackContract = typeof(IStatusServiceCallback))]
    public interface IStatusService
    {
        [OperationContract]
        [FaultContract(typeof(APIFault))]
        Task<uint> GetVersionAsync();

        [OperationContract]
        [FaultContract(typeof(APIFault))]
        Task CheckInAsync(Guid checkInGuid);

        [OperationContract]
        [FaultContract(typeof(APIFault))]
        Task AvailableAppCheckInAsync(Guid checkInGuid);

        [OperationContract]
        [FaultContract(typeof(APIFault))]
        Task<Guid> GetCurrentCheckInIdAsync();

        [OperationContract]
        [FaultContract(typeof(APIFault))]
        Task<AppInstallStatusReport> GetAppStatusAsync(Guid appId);

        [OperationContract]
        [FaultContract(typeof(APIFault))]
        Task<AppInstallStatusReport[]> GetAllAppsStatusAsync();
    }

    // Callback Contract
    public interface IStatusServiceCallback
    {
        [OperationContract(IsOneWay = true)]
        void SyncComplete(SyncResult result);

        [OperationContract(IsOneWay = true)]
        void AppStatusUpdate(AppInstallStatusReport report);

        [OperationContract(IsOneWay = true)]
        void DownloadProgressUpdate(DownloadProgressReport report);
    }

    // Data Contracts - namespace MUST match the server's CLR namespace
    [DataContract(Namespace = Ns.Dc)]
    public class AppInstallStatusReport
    {
        [DataMember]
        public Guid AppId { get; set; }

        [DataMember]
        public bool Required { get; set; }

        [DataMember]
        public AppInstallStatus Status { get; set; }

        [DataMember(Order = 3)]
        public AppInstallStatus2 Status2 { get; set; }

        [DataMember]
        public Applicability ApplicabilityCode { get; set; }

        [DataMember(Order = 3)]
        public Applicability2 ApplicabilityCode2 { get; set; }

        [DataMember]
        public int ErrorCode { get; set; }

        [DataMember]
        public bool CustomError { get; set; }
    }

    [DataContract(Namespace = Ns.Dc)]
    public class SyncResult
    {
        [DataMember]
        public Guid SessionId { get; set; }

        [DataMember]
        public bool Success { get; set; }

        [DataMember]
        public int ErrorCode { get; set; }
    }

    [DataContract(Namespace = Ns.Dc)]
    public class DownloadProgressReport
    {
        [DataMember]
        public Guid AppId { get; set; }

        [DataMember]
        public long BytesDownloaded { get; set; }

        [DataMember]
        public long TotalSizeInBytes { get; set; }
    }

    [DataContract(Namespace = Ns.Dc)]
    public class APIFault
    {
        [DataMember]
        public FaultContractErrorCodes ErrorID { get; set; }

        [DataMember]
        public string ErrorDetails { get; set; }
    }

    // Enums - also need namespace to match server serialization
    [DataContract(Namespace = Ns.Dc)]
    public enum AppInstallStatus
    {
        [EnumMember] Unknown                            = 0,
        [EnumMember] Installed                          = 1000,
        [EnumMember] Installing                         = 1001,
        [EnumMember] InstalledButDependenciesNotPresent  = 1002,
        [EnumMember] InstallingPendingReboot            = 1003,
        [EnumMember] InstalledPendingReboot             = 1004,
        [EnumMember] NotApplicable                      = 2000,
        [EnumMember] Failed                             = 3000
    }

    [DataContract(Namespace = Ns.Dc)]
    public enum AppInstallStatus2
    {
        [EnumMember] Unknown                            = 0,
        [EnumMember] Installed                          = 1000,
        [EnumMember] InstalledButDependenciesNotPresent  = 1001,
        [EnumMember] InstalledPendingReboot             = 1002,
        [EnumMember] Installing                         = 2000,
        [EnumMember] InstallingPendingReboot            = 2001,
        [EnumMember] NotApplicable                      = 3000,
        [EnumMember] Failed                             = 4000,
        [EnumMember] UninstalledByGateway               = 5000,
        [EnumMember] NotInstalled                       = 5001,
        [EnumMember] Uninstalling                       = 6000,
        [EnumMember] UninstallFailed                    = 7000
    }

    [DataContract(Namespace = Ns.Dc)]
    public enum Applicability
    {
        [EnumMember] Unknown                            = -1,
        [EnumMember] Applicable                         = 0,
        [EnumMember] RequirementsNotMet                 = 1,
        [EnumMember] HostPlatformNotApplicable          = 3,
        [EnumMember] ProcessorArchitectureNotApplicable = 1000,
        [EnumMember] MinimumDiskSpaceNotMet             = 1001,
        [EnumMember] MinimumOSVersionNotMet             = 1002,
        [EnumMember] MinimumPhysicalMemoryNotMet        = 1003,
        [EnumMember] MinimumLogicalProcessorCountNotMet = 1004,
        [EnumMember] MinimumCPUSpeedNotMet              = 1005,
        [EnumMember] FileSystemRequirementRuleNotMet    = 1006,
        [EnumMember] RegistryRequirementRuleNotMet      = 1007,
        [EnumMember] ScriptRequirementRuleNotMet        = 1008
    }

    [DataContract(Namespace = Ns.Dc)]
    public enum Applicability2
    {
        [EnumMember] Unknown                            = -1,
        [EnumMember] Applicable                         = 0,
        [EnumMember] RequirementsNotMet                 = 1,
        [EnumMember] HostPlatformNotApplicable          = 3,
        [EnumMember] ProcessorArchitectureNotApplicable = 1000,
        [EnumMember] MinimumDiskSpaceNotMet             = 1001,
        [EnumMember] MinimumOSVersionNotMet             = 1002,
        [EnumMember] MinimumPhysicalMemoryNotMet        = 1003,
        [EnumMember] MinimumLogicalProcessorCountNotMet = 1004,
        [EnumMember] MinimumCPUSpeedNotMet              = 1005,
        [EnumMember] FileSystemRequirementRuleNotMet    = 1006,
        [EnumMember] RegistryRequirementRuleNotMet      = 1007,
        [EnumMember] ScriptRequirementRuleNotMet        = 1008
    }

    [DataContract(Namespace = Ns.Dc)]
    public enum FaultContractErrorCodes
    {
        [EnumMember] GetVersion          = 0,
        [EnumMember] CheckIn             = 1,
        [EnumMember] GetApp              = 2,
        [EnumMember] GetAllApps          = 3,
        [EnumMember] GetCurrentCheckInId = 4
    }

    [DataContract(Namespace = Ns.Dc)]
    public enum CheckInErrorCode
    {
        [EnumMember] Unknown                        = 0,
        [EnumMember] AppWorkloadNotSwitchedToIntune = 1,
        [EnumMember] TooManyWin32AppSyncsInQueue    = 2
    }
}
