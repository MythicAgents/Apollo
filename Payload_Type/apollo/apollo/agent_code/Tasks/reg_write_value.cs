#define COMMAND_NAME_UPPER

#if DEBUG
#define REG_WRITE_VALUE
#endif

#if REG_WRITE_VALUE

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Utils;
using Microsoft.Win32;
using System;
using System.Runtime.Serialization;

namespace Tasks
{
    public class reg_write_value : Tasking
    {
        [DataContract]
        internal struct RegWriteParameters
        {
            [DataMember(Name = "hive")]
            public string Hive;
            [DataMember(Name = "key")]
            public string Key;
            [DataMember(Name = "value_name")]
            public string ValueName;
            [DataMember(Name = "value_value")]
            public string ValueValue;
            [DataMember(Name = "value_type")]
            public int ValueType;
        }
        public reg_write_value(IAgent agent, ApolloInterop.Structs.MythicStructs.MythicTask data) : base(agent, data)
        {
        }

        private bool SetValue(string hive, string subkey, string valueName, object valueValue, RegistryValueKind RegType)
        {
            using (RegistryKey regKey = RegistryUtils.GetRegistryKey(hive, subkey, true))
            {
                regKey.SetValue(valueName, valueValue, RegType);
                return true;
            }
        }


        public override void Start()
        {
            MythicTaskResponse resp;
            RegWriteParameters parameters = _jsonSerializer.Deserialize<RegWriteParameters>(_data.Parameters);
            bool bRet;
            bRet = SetValue(parameters.Hive, parameters.Key, parameters.ValueName, parameters.ValueValue, (RegistryValueKind)parameters.ValueType);
            if (bRet)
            {
                resp = CreateTaskResponse(
                    $"Successfully set {parameters.ValueName} to {parameters.ValueValue}",
                    true,
                    "completed",
                    new IMythicMessage[1]
                    {
                        Artifact.RegistryWrite(parameters.Hive, parameters.Key, parameters.ValueName, parameters.ValueValue)
                    });
            }
            else
            {
                resp = CreateTaskResponse(
                    $"Failed to set {parameters.ValueName}", true, "error");
            }

            // Your code here..
            // Then add response to queue
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}

#endif