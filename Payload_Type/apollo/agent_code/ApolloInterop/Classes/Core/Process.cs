using ApolloInterop.Classes.Events;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.ApolloStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace ApolloInterop.Classes.Core
{
    public abstract class Process : IProcess
    {
        public string Application { get; protected set; }
        public string CommandLine { get; protected set; }
        protected bool _startSuspended;
        public bool HasExited { get; protected set; }
        public int ExitCode { get; protected set; }
        public uint PID { get; protected set; }
        public string StdOut { get; protected set; } = "";
        public string StdErr { get; protected set; } = "";
        public IntPtr Handle { get; protected set; }
        protected IAgent _agent;
        public event EventHandler<StringDataEventArgs> OutputDataReceived;
        public event EventHandler<StringDataEventArgs> ErrorDataReceieved;
        public event EventHandler Exit;
        
        public void OnOutputDataReceived(object sender, StringDataEventArgs args)
        {
            OutputDataReceived?.Invoke(sender, args);
        }

        public void OnErrorDataRecieved(object sender, StringDataEventArgs args)
        {
            ErrorDataReceieved?.Invoke(sender, args);
        }

        public abstract void Kill();

        public void OnExit(object sender, EventArgs args)
        {
            Exit?.Invoke(sender, args);
        }
        public Process(IAgent agent, string lpApplication, string lpArguments=null, bool startSuspended = false)
        {
            _agent = agent;
            if (string.IsNullOrEmpty(lpApplication) && string.IsNullOrEmpty(lpArguments))
            {
                throw new Exception("Application and arguments cannot be null.");
            }
            if (string.IsNullOrEmpty(lpArguments))
            {
                CommandLine = lpApplication;
                Application = lpApplication;
            } else if (string.IsNullOrEmpty(lpApplication))
            {
                CommandLine = lpArguments;
            } else
            {
                Application = lpApplication;
                CommandLine = $"{lpApplication} {lpArguments}";
            }
            _startSuspended = startSuspended;
        }

        public abstract bool Inject(byte[] code, string arguments = "");

        public abstract bool Start();

        public abstract bool StartWithCredentials(ApolloLogonInformation logonInfo);

        public abstract bool StartWithCredentials(IntPtr hToken);

        public abstract void WaitForExit();

        public abstract void WaitForExit(int milliseconds);
    }
}
