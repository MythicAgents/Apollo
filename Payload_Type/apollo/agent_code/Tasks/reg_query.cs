#define COMMAND_NAME_UPPER

#if DEBUG
#define REG_QUERY
#endif

#if REG_QUERY

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Utils;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using ST = System.Threading.Tasks;

namespace Tasks
{
    public class reg_query : Tasking
    {
        [DataContract]
        internal struct RegQueryParameters
        {
            [DataMember(Name = "hive")]
            public string Hive;
            [DataMember(Name = "key")]
            public string Key;
        }
        [DataContract]
        internal struct RegQueryResult
        {
            [DataMember(Name = "hive")]
            public string Hive;
            [DataMember(Name = "name")]
            public string Name;
            [DataMember(Name = "full_name")]
            public string FullName;
            [DataMember(Name = "value")]
            public string Value;
            [DataMember(Name = "value_type")]
            public string Type;
            [DataMember(Name = "result_type")]
            public string ResultType;
        }
        public reg_query(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
        {
        }


        private static string[] GetValueNames(string hive, string subkey)
        {
            using (RegistryKey regKey = RegistryUtils.GetRegistryKey(hive, subkey))
            {
                return regKey.GetValueNames();
            }
        }

        private static object GetValue(string hive, string subkey, string key)
        {
            using (RegistryKey regKey = RegistryUtils.GetRegistryKey(hive, subkey))
            {
                return regKey.GetValue(key);
            }
        }

        private static string[] GetSubKeys(string hive, string subkey)
        {
            using (RegistryKey regKey = RegistryUtils.GetRegistryKey(hive, subkey))
            {
                return regKey.GetSubKeyNames();
            }
        }

        private void SetValueType(object tmpVal, ref RegQueryResult res)
        {
            if (tmpVal is String)
            {
                res.Value = string.IsNullOrEmpty(tmpVal.ToString()) ? "(value not set)" : tmpVal.ToString();
                res.Type = "string";
            }
            else if (tmpVal is int)
            {
                res.Value = tmpVal.ToString();
                res.Type = "int";
            }
            else if (tmpVal is byte[])
            {
                res.Value = BitConverter.ToString((byte[])tmpVal);
                res.Type = "byte[]";
            }
            else if (tmpVal is null)
            {
                res.Value = "(value not set)";
                res.Type = "null";
            }
            else
            {
                res.Value = tmpVal.ToString();
                res.Type = "unknown";
            }
        }


        public override void Start()
        {
            TaskResponse resp;
            RegQueryParameters parameters = _jsonSerializer.Deserialize<RegQueryParameters>(_data.Parameters);
            List<RegQueryResult> results = new List<RegQueryResult>();
            List<IMythicMessage> artifacts = new List<IMythicMessage>();
            string error = "";

            try
            {
                string[] subkeys = GetSubKeys(parameters.Hive, parameters.Key);
                artifacts.Add(Artifact.RegistryRead(parameters.Hive, parameters.Key));
                foreach (string subkey in subkeys)
                {
                    results.Add(new RegQueryResult
                    {
                        Name = subkey,
                        FullName = parameters.Key.EndsWith("\\") ? $"{parameters.Key}{subkey}" : $"{parameters.Key}\\{subkey}",
                        Hive = parameters.Hive,
                        ResultType = "key"
                    });
                }
            }
            catch (Exception ex)
            {
                error = ex.Message;
            }

            try
            {
                object tmpVal;
                string[] subValNames = GetValueNames(parameters.Hive, parameters.Key);
                foreach (string valName in subValNames)
                {
                    RegQueryResult res = new RegQueryResult
                    {
                        Name = valName,
                        FullName = parameters.Key,
                        Hive = parameters.Hive,
                        ResultType = "value"
                    };
                    try
                    {
                        tmpVal = GetValue(parameters.Hive, parameters.Key, valName);
                    }
                    catch (Exception ex)
                    {
                        tmpVal = ex.Message;
                    }

                    SetValueType(tmpVal, ref res);
                    results.Add(res);
                    artifacts.Add(Artifact.RegistryRead(parameters.Hive, $"{parameters.Key} {valName}"));
                }
            }
            catch (Exception ex)
            {
                error += $"\n{ex.Message}";
            }

            if (results.Count == 0)
            {
                resp = CreateTaskResponse(error, true, "error", artifacts.ToArray());
            }
            else
            {
                resp = CreateTaskResponse(
                    _jsonSerializer.Serialize(results.ToArray()), true, "completed", artifacts.ToArray());
            }


            // Your code here..
            // Then add response to queue
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}

#endif