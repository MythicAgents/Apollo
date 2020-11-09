using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;

namespace IPC
{
    [Serializable]
    public class KeystrokeMessage
    {
        public string User;
        public string WindowTitle;
        public string Keystrokes;
    }


    [Serializable]
    public class KillLoggerMessage
    {
        public static bool exit = true;
    }

    public class KeystrokeMessageBinder : SerializationBinder
    {
        public override Type BindToType(string assemblyName, string typeName)
        {
            // One way to discover expected types is through testing deserialization
            // of **valid** data and logging the types used.

            //Console.WriteLine($"BindToType('{assemblyName}', '{typeName}')");

            if (typeName == "IPC.KeystrokeMessage")
            {
                return typeof(KeystrokeMessage);
            }
            else if (typeName == "IPC.KillLoggerMessage")
            {
                return typeof(KillLoggerMessage);
            }
            else
            {
                throw new ArgumentException("Unexpected type", nameof(typeName));
            }
        }
    }

}
