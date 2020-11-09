#define COMMAND_NAME_UPPER

#if DEBUG
#undef NET_LOCALGROUP
#define NET_LOCALGROUP
#endif


#if NET_LOCALGROUP
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
    class NetLocalGroup
    {
        public static void Execute(Job job, Agent implant)
        {
            Task task = job.Task;
            string computer = task.parameters.Trim();

            if (string.IsNullOrEmpty(computer))
            {
                computer = Environment.GetEnvironmentVariable("COMPUTERNAME");
            }

            try
            {
                var results = ADUtils.GetLocalGroups(computer);
                job.SetComplete(results);
            } catch (Exception ex)
            {
                job.SetError($"Failed to get local groups. Reason: {ex.Message}");
            }
        }
    }
}
#endif