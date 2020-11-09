#define COMMAND_NAME_UPPER


#if DEBUG
#undef SLEEP
#define SLEEP
#endif

#if SLEEP

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using Apollo.Jobs;
using Apollo.Tasks;
using System.Runtime.CompilerServices;

namespace Apollo.CommandModules
{
    class Sleep
    {
        /// <summary>
        /// Update the agent sleep time.
        /// </summary>
        /// <param name="job">
        /// Job associated with this task. The updated sleep time
        /// of the agent is located in job.Task.parameters and must
        /// be a valid unsigned integer.
        /// </param>
        /// <param name="agent">Agent associated with this task.</param>
        public static void Execute(Job job, Agent agent)
        {
            Task task = job.Task;
            double jitter = 0;
            try
            {
                string[] parts = task.parameters.Split(' ');
                int sleep = (int)Convert.ToUInt32(parts[0]);
                if (parts.Length >= 2)
                {
                    jitter = ((double)Convert.ToUInt32(parts[1]) / (double)100);
                }
                Debug.WriteLine("[-] DispatchTask - Tasked to change sleep to: " + sleep);
                agent.SleepInterval = sleep * 1000;
                agent.Jitter = jitter;
                if (sleep == 0)
                {
                    job.SetComplete("Tasked agent to become interactive.");
                } else
                {
                    job.SetComplete($"Sleep updated to {sleep} seconds.");
                }
            }
            catch
            {
                job.SetError("Please provide an integer value");
            }
        }
    }
}
#endif