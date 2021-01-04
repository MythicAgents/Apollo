#define COMMAND_NAME_UPPER

#if RPORTFWD

using Apollo.Jobs;
using Apollo.RPortFwdProxy;
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
    class RPortFwd
    {
        public struct RPortFwdParams
        {
            public string action;
            public int port;
            public int rport;
            public string rip;
        }
        public static void Execute(Job job, Agent agent)
        {
            Task task = job.Task;

            JObject json = (JObject)JsonConvert.DeserializeObject(task.parameters);
            string action = json.Value<string>("action");
            //SocksParams socksParams = Newtonsoft.Json.JsonConvert.DeserializeObject<SocksParams>(job.Task.parameters);
            string port = "0";
            string rport = "0";
            string rip = "";

            switch (action)
            {
                case "start":
                    try
                    {
                        port = json.Value<string>("port");
                        rport = json.Value<string>("rport");
                        rip = json.Value<string>("rip");
                    }
                    catch (Exception e)
                    {
                        job.SetError("Parameters to start Port Forward not found");
                        return;
                    }
                    if (RPortFwdController.IsActive(port))
                    {
                        job.SetError("Port Forward is already active in that port.");
                        return;
                    }

                    RPortFwdController.StartClientPort(port, rport, rip);

                    job.SetComplete($"Port Forward connection started.");

                    break;
                case "stop":
                    try
                    {
                        port = json.Value<string>("port");
                    }
                    catch (Exception e)
                    {
                        job.SetError("Parameters to stop Port Forward not found");
                        return;
                    }
                    if (RPortFwdController.StopClientPort(port))
                    {
                        job.SetComplete("Port Forward connection stopped.");
                    }
                    else
                    {
                        job.SetComplete("Could not stop Port Forward in that port.");
                    }
                    break;
                case "flush":
                    //RPortFwdController.FlushClient();
                    job.SetComplete("Port Forward flush not implemented yet.");
                    break;
                case "list":
                    string list = RPortFwdController.ListPortForward();
                    job.SetComplete(list);
                    break;
                default:
                    job.SetError("Invalid action.");
                    break;
            }

        }
    }
}

#endif
