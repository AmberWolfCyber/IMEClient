namespace IMEClient.plugins
{
    /// <summary>
    /// DXSetup-specific NSIS race condition.
    /// The DirectX installer extracts to a .tmp folder and loads dxupdate.dll from it.
    /// </summary>
    internal class DXSetup : NSISPlugin
    {
        public override string PayloadFileName => "dxupdate.dll";

        public DXSetup(string[] args) : base(args)
        {
        }
    }
}