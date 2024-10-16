#define COMMAND_NAME_UPPER

#if DEBUG
#define SLEEP
#endif

#if SLEEP

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Runtime.Serialization;
using static Tasks.make_token;

namespace Tasks
{
    public class sleep : Tasking
    {
        [DataContract]
        internal struct SleepParameters
        {
            [DataMember(Name = "interval")]
            public int Sleep;
            [DataMember(Name = "jitter")]
            public int Jitter;
        }
        public sleep(IAgent agent, MythicTask data) : base(agent, data)
        {
        }


        public override void Start()
        {
            MythicTaskResponse resp;
            SleepParameters parameters = _jsonSerializer.Deserialize<SleepParameters>(_data.Parameters);
            if (parameters.Sleep >= 0)
            {
                if (parameters.Jitter >= 0)
                {
                    _agent.SetSleep(parameters.Sleep, parameters.Jitter);
                }
                else
                {
                    _agent.SetSleep(parameters.Sleep);
                }
            }
            resp = CreateTaskResponse("", true);
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);

        }
    }
}
#endif