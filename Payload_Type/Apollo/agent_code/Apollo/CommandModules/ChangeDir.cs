#define COMMAND_NAME_UPPER

#if DEBUG
#undef CD
#define CD
#endif

#if CD
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using Apollo.Jobs;
using Apollo.Tasks;

namespace Apollo.CommandModules
{
    /// <summary>
    /// Task responsible for changing directories.
    /// </summary>
    public class ChangeDir
    {
        /// <summary>
        /// Change directory based on the Job.Task.parameters
        /// </summary>
        /// <param name="job">
        /// Job associated with this task. job.Task.parameters
        /// will be a string to the file path to change into.
        /// </param>
        /// <param name="agent">Agent this task is run on.</param>
        public static void Execute(Job job, Agent agent)
        {
            Task task = job.Task;
            string path = task.parameters;
            try
            {
                Directory.SetCurrentDirectory(path);
                job.SetComplete($"Changed to directory {Directory.GetCurrentDirectory()}");
            }
            catch (Exception e)
            {
                job.SetError($"Error changing directory: {e.Message}");
            }
        }
    }
}
#endif