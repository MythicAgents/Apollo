using System;
using System.Diagnostics;
using System.Linq;

namespace Utils
{
    class DebugUtils
    {
        public static void DebugWriteLine(string body)
        {
#if DEBUG
            var trace = new StackTrace();
            var methodBase = trace.GetFrame(1).GetMethod();
            var output = string.Format("[{0}] [{1}:{2}] {3}", System.DateTime.Now, methodBase.ReflectedType.Name, methodBase.Name, body);
            Console.WriteLine(output);
#endif
        }
        public static void DebugWriteLine(string formatString, params string[] args)
        {
#if DEBUG
            var trace = new StackTrace();
            var methodBase = trace.GetFrame(1).GetMethod();
            var formattedString = string.Format(formatString, args);
            var output = string.Format("[{0}] [{1}:{2}] {3}", System.DateTime.Now, methodBase.ReflectedType.Name, methodBase.Name, formattedString);
            Console.WriteLine(output);
#endif
        }
    }
}
