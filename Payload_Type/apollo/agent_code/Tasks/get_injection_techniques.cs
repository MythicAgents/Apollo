#define COMMAND_NAME_UPPER

#if DEBUG
#define GET_INJECTION_TECHNIQUES
#endif

#if GET_INJECTION_TECHNIQUES

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using ST = System.Threading.Tasks;

namespace Tasks
{
    public class get_injection_techniques : Tasking
    {
        [DataContract]
        internal struct InjectionTechniqueResult
        {
            [DataMember(Name = "name")]
            public string Name;
            [DataMember(Name = "is_current")]
            public bool IsCurrent;
        }
        public get_injection_techniques(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
        {
        }
        

        public override void Start()
        {
            TaskResponse resp;
            string[] techniques = _agent.GetInjectionManager().GetTechniques();
            Type cur = _agent.GetInjectionManager().GetCurrentTechnique();
            List<InjectionTechniqueResult> results = new List<InjectionTechniqueResult>();
            foreach (string t in techniques)
            {
                results.Add(new InjectionTechniqueResult
                {
                    Name = t,
                    IsCurrent = t == cur.Name
                });
            }

            resp = CreateTaskResponse(
                _jsonSerializer.Serialize(results.ToArray()), true);
            // Your code here..
            // Then add response to queue
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}

#endif