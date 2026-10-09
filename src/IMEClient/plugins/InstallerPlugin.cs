using System;
using System.IO;

namespace IMEClient.plugins
{
    internal abstract class InstallerPlugin
    {
        protected readonly string[] Args;

        /// <summary>Name shown in console output. Defaults to class name.</summary>
        public virtual string Name => GetType().Name;

        public InstallerPlugin(string[] args)
        {
            Args = args;
        }

        /// <summary>
        /// Called for every file-system event under C:\.
        /// Each plugin decides whether the event is relevant and how to react.
        /// </summary>
        public abstract void OnFileEvent(object sender, FileSystemEventArgs e);
    }
}
