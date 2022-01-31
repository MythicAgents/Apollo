using ApolloInterop.Interfaces;
using ApolloInterop.Structs.ApolloStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Process
{
    public class ProcessManager : IProcessManager
    {
        private bool _blockDlls = false;
        private int _ppid = System.Diagnostics.Process.GetCurrentProcess().Id;
        private string _applicationx64 = @"C:\Windows\System32\rundll32.exe";
        private string _applicationx86 = @"C:\Windows\SysWOW64\rundll32.exe";
        private string _argumentsx64 = null;
        private string _argumentsx86 = null;

        private IAgent _agent;

        public ProcessManager(IAgent agent)
        {
            _agent = agent;
        }

        public bool BlockDLLs(bool status)
        {
            _blockDlls = status;
            return true;
        }

        public ApplicationStartupInfo GetStartupInfo(bool x64 = true)
        {
            ApplicationStartupInfo results = new ApplicationStartupInfo();
            results.Application = x64 ? _applicationx64 : _applicationx86;
            results.Arguments = x64 ? _argumentsx64 : _argumentsx86;
            results.ParentProcessId = _ppid;
            results.BlockDLLs = _blockDlls;
            return results;
        }

        public ApolloInterop.Classes.Core.Process NewProcess(string lpApplication, string lpArguments, bool startSuspended = false)
        {
            return new SacrificialProcess(
                _agent,
                lpApplication,
                lpArguments,
                startSuspended);
        }

        public bool SetPPID(int pid)
        {
            bool bRet = false;
            try
            {
                var curProc = System.Diagnostics.Process.GetCurrentProcess();
                var proc = System.Diagnostics.Process.GetProcessById(pid);
                if (proc.SessionId != curProc.SessionId)
                    bRet = false;
                else
                {
                    bRet = true;
                    _ppid = pid;
                }
            }
            catch { }
            return bRet;
        }

        public bool SetSpawnTo(string lpApplication, string lpCommandLine = null, bool x64 = true)
        {
            if (x64)
            {
                _applicationx64 = lpApplication;
                _argumentsx64 = lpCommandLine;
            }
            else
            {
                _applicationx86 = lpApplication;
                _argumentsx86 = lpCommandLine;
            }
            return true;
        }
    }
}
