#define COMMAND_NAME_UPPER

#if DEBUG
#undef NET_DCLIST
#define NET_DCLIST
#endif


#if NET_DCLIST
using Newtonsoft.Json;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using Mythic.Structs;
using Apollo.Jobs;
using Apollo.MessageInbox;
using Apollo.Tasks;
using Utils;
using System.Runtime.InteropServices;

namespace Apollo.CommandModules
{
    class NetDCList
    {
        public static void Execute(Job job, Agent implant)
        {
            Task task = job.Task;

            string domain = task.parameters.Trim();
            try
            {
                var results = ADUtils.FindAllDomainControllers(domain);
                job.SetComplete(results);
            }
            catch (Exception ex)
            {
                job.SetError($"Error fetching domain controllers. Reason: {ex.Message}");
            }
        }
    }
}
#endif