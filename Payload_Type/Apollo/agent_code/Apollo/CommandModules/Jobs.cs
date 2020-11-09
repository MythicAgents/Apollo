#define COMMAND_NAME_UPPER

#if DEBUG
#undef JOBS
#undef JOBKILL
#define JOBS
#define JOBKILL
#endif

#if JOBS || JOBKILL
using System;
using System.Linq;
using System.Threading;
using Apollo.Jobs;
using Apollo.Tasks;

namespace Apollo.CommandModules
{
    public class Jobs
    { 
        /// <summary>
        /// Executes taskings related to job tasks. Depending
        /// on the task issued, valid taskings are "jobs" and
        /// "jobkill".
        /// </summary>
        /// <param name="job">Job associated with this task.</param>
        /// <param name="implant">Agent associated with this job.</param>
        public static void Execute(Job job, Agent implant)
        {
            Task task = job.Task;
            switch(task.command)
            {
#if JOBS
                case "jobs":
                    var runningJobs = JobManager.GetJobs();
                    if (runningJobs.Length > 0)
                        job.SetComplete(runningJobs);
                    else
                        job.SetComplete("No jobs running at this time.");
                    break;
#endif
#if JOBKILL
                case "jobkill":
                    try
                    {
                        JobManager.KillJob(Convert.ToInt32(task.parameters));
                        job.SetComplete($"Killed job {task.parameters}");
                    }
                    catch (Exception ex)
                    {
                        job.SetError($"Failed to kill job {task.parameters}. Reason: {ex.Message}\n\tStackTrace: {ex.StackTrace}");
                    }
                    break;
#endif
                default:
                    job.SetError("Unsupported code path.");
                    break;
            }
        }
    }
}
#endif