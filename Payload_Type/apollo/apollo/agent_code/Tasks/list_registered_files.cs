#define COMMAND_NAME_UPPER

#if DEBUG
#define LIST_REGISTERED_FILES
#endif

#if LIST_REGISTERED_FILES


using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Runtime.Serialization;

namespace Tasks
{
    public class list_registered_files : Tasking
    {

        public list_registered_files(IAgent agent, MythicTask mythicTask) : base(agent, mythicTask)
        {

        }


        public override void Start()
        {
            MythicTaskResponse resp;
            string[] Files = _agent.GetFileManager().ListFiles();

            resp = CreateTaskResponse(_jsonSerializer.Serialize(Files), true);

            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}
#endif