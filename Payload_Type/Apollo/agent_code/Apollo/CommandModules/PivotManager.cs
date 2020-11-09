#define COMMAND_NAME_UPPER

#if DEBUG
#undef PIVOT
#define PIVOT
#endif

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Apollo.Jobs;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Apollo.CommandModules
{
    class PivotManager
    {
        public static void Execute(Job job, Agent implant)
        {
            
            switch (job.Task.command)
            {
                default:
                    job.SetComplete("Not implemented.");
                    break;
            }
        }
    }
}
