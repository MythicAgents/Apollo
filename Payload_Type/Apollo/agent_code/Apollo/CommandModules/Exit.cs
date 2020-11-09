#define COMMAND_NAME_UPPER

#if DEBUG
#undef EXIT
#define EXIT
#endif

#if EXIT
using System;
using Apollo.Jobs;
using System.Runtime.InteropServices;
using Apollo.Tasks;
using System.Windows.Forms.PropertyGridInternal;
using System.Runtime.Versioning;
using System.Linq;
using System.Text;
using System.Runtime.CompilerServices;

namespace Apollo.CommandModules
{
    public class Exit
    {
        /// <summary>
        /// Exit the process, terminating the agent.
        /// </summary>
        /// <param name="job">Job associated with the task.</param>
        /// <param name="implant">Agent to run this on.</param>
        public static void Execute(Job job, Agent implant)
        {
            Task task = job.Task;
            try
            {
                job.SetComplete("Exited.");
            }
            catch (Exception e)
            {
                job.SetError(string.Format("Error exiting agent: {0}", e.Message));
            }
            
            Environment.Exit(0);
        }
    }
}
#endif