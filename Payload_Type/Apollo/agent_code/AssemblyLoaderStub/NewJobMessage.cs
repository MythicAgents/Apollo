using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;

namespace IPC
{
    [Serializable]
    public class PowerShellJobMessage
    {
        public string LoadedScript;
        public string Command;
        public string ID;
    }

    [Serializable]
    public class PowerShellTerminatedMessage
    {
        public string Message;
    }

    public class PowerShellJobMessageBinder : SerializationBinder
    {
        public override Type BindToType(string assemblyName, string typeName)
        {
            if (typeName == "IPC.PowerShellJobMessage")
            {
                return typeof(PowerShellJobMessage);
            }
            else if (typeName == "IPC.PowerShellTerminatedMessage")
            {
                return typeof(PowerShellTerminatedMessage);
            } else
            {
                throw new ArgumentException("Unexpected type", nameof(typeName));
            }
        }
    }
}
