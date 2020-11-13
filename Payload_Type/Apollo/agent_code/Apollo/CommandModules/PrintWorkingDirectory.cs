#define COMMAND_NAME_UPPER

#if DEBUG
#undef PWD
#define PWD
#endif

#if PWD

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using Apollo.Jobs;
using Apollo.Tasks;

namespace Apollo.CommandModules
{
    public class PrintWorkingDirectory
    {
        public static void Execute(Job job, Agent agent)
        {
            Task task = job.Task;
            
            try
            {
                job.SetComplete($"{Directory.GetCurrentDirectory()}");
            }
            catch (Exception e)
            {
                job.SetError($"Error in pwd: {e.Message}");
            }
        }
    }
}
#endif