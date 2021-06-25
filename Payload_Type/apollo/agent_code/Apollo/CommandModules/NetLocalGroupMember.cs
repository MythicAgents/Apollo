#define COMMAND_NAME_UPPER

#if DEBUG
#undef NET_LOCALGROUP_MEMBER
#define NET_LOCALGROUP_MEMBER
#endif


#if NET_LOCALGROUP_MEMBER
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
    class NetLocalGroupMember
    {
        public struct NetLocalGroupArguments
        {
            public string computer;
            public string group;
        }

        public static void Execute(Job job, Agent implant)
        {
            Task task = job.Task;

            NetLocalGroupArguments args = JsonConvert.DeserializeObject<NetLocalGroupArguments>(task.parameters);
            
            if (string.IsNullOrEmpty(args.group))
            {
                job.SetError("Missing required parameter: group");
                return;
            }
            if (string.IsNullOrEmpty(args.computer))
                args.computer = Environment.GetEnvironmentVariable("COMPUTERNAME");
            try
            {
                var results = ADUtils.GetLocalGroupMembers(args.computer, args.group);
                job.SetComplete(results);
            } catch (Exception ex)
            {
                job.SetError($"Error fetching members of {args.group}. LastWin32Error: {Marshal.GetLastWin32Error()}");
            }
        }

    }
}
#endif