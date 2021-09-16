using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO.Pipes;
using System.Security.AccessControl;

namespace Apollo.Api.IO
{
    public static class Pipes
    {
        public static NamedPipeServerStream CreateAsyncNamedPipeServer(
            string pipeName,
            bool allowNetworkLogon = false,
            PipeTransmissionMode transmissionMode = PipeTransmissionMode.Byte)
        {
            PipeSecurity pipeSecurityDescriptor = new PipeSecurity();
            PipeAccessRule everyoneAllowedRule = new PipeAccessRule("Everyone", PipeAccessRights.ReadWrite, AccessControlType.Allow);
            PipeAccessRule networkAllowRule;
            if (allowNetworkLogon)
            {
                networkAllowRule = new PipeAccessRule("Network", PipeAccessRights.ReadWrite, AccessControlType.Allow);
            }
            else
            {
                networkAllowRule = new PipeAccessRule("Network", PipeAccessRights.ReadWrite, AccessControlType.Deny);
            }
            pipeSecurityDescriptor.AddAccessRule(everyoneAllowedRule);
            pipeSecurityDescriptor.AddAccessRule(networkAllowRule);


            return new NamedPipeServerStream(pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 32768 * 6, 32768 * 6, pipeSecurityDescriptor);
        }
    }
}
