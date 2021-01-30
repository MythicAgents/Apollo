using System;
using System.Collections.Generic;
using System.Runtime.Serialization;

namespace IPC
{ 

   [Serializable]
   public class ScreenshotMessage
    {
        public byte[] Capture;
        public string ErrorMessage;
    }

    /// <summary>
    /// Used to signal the end of job messages.
    /// </summary>
    [Serializable]
    public class ScreenshotTerminationMessage{}

    public class ScreenshotMessageBinder : SerializationBinder
    {
        public override Type BindToType(string assemblyName, string typeName)
        {
#if DEBUG
            Console.WriteLine($"BindToType('{assemblyName}', '{typeName}')");
#endif
            if (typeName == "IPC.ScreenshotMessage")
            {
                return typeof(ScreenshotMessage);
            }
            else if (typeName == "IPC.ScreenshotTerminationMessage")
            {
                return typeof(ScreenshotTerminationMessage);
            }
            else
            {
                throw new ArgumentException("Unexpected type", nameof(typeName));
            }
        }
    }
}
