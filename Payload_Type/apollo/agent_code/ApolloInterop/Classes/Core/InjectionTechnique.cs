using ApolloInterop.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Classes.Core
{
    public abstract class InjectionTechnique : IInjectionTechnique
    {
        protected byte[] _code;
        protected int _processId;
        protected IntPtr _hProcess = IntPtr.Zero;
        protected IAgent _agent;
        public InjectionTechnique(IAgent agent, byte[] code, int pid)
        {
            _code = code;
            _processId = pid;
            _agent = agent;
            _hProcess = System.Diagnostics.Process.GetProcessById(pid).Handle;
        }

        public InjectionTechnique(IAgent agent, byte[] code, IntPtr hProcess)
        {
            _code = code;
            _hProcess = hProcess;
            _agent = agent;
        }

        public abstract bool Inject(string arguments = "");
    }
}
