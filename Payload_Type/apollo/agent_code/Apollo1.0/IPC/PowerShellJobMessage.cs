#define COMMAND_NAME_UPPER

#if DEBUG
#undef PSIMPORT
#undef PSCLEAR
#undef LIST_SCRIPTS
#undef POWERPICK
#undef PSINJECT
#define POWERPICK
#define PSINJECT
#define PSIMPORT
#define PSCLEAR
#define LIST_SCRIPTS
#endif

#if POWERPICK || PSINJECT || PSIMPORT || PSCLEAR || LIST_SCRIPTS

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;

namespace IPC
{
    [Serializable]
    class PowerShellJobMessage
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
            // One way to discover expected types is through testing deserialization
            // of **valid** data and logging the types used.

            
            if (typeName == "IPC.PowerShellJobMessage")
            {
                return typeof(PowerShellJobMessage);
            }
            else if (typeName == "IPC.PowerShellTerminatedMessage")
            {
                return typeof(PowerShellTerminatedMessage);
            }
            else
            {
                throw new ArgumentException("Unexpected type", nameof(typeName));
            }
        }
    }
}
#endif