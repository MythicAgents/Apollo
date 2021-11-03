#define COMMAND_NAME_UPPER

#if DEBUG
#define REG_QUERY
#endif

#if REG_QUERY

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
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

        public override void Kill()
        {
            base.Kill();
        }

        private static string[] GetValueNames(string hive, string subkey)
        {
            switch (hive)
            {
                case "HKCU":
                    using (RegistryKey regKey = Registry.CurrentUser.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            return regKey.GetValueNames();
                        }
                    }
                    break;
                case "HKLM":
                    using (RegistryKey regKey = Registry.LocalMachine.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            return regKey.GetValueNames();
                        }
                    }
                    break;
                case "HKCR":
                    using (RegistryKey regKey = Registry.ClassesRoot.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            return regKey.GetValueNames();
                        }
                    }
                    break;
                default:
                    throw new Exception("Invalid string format. Key must be of the form HKLM:, HKCU:, or HKCR");
            }
            return null;
        }

        private static object GetValue(string hive, string subkey, string key)
        {
            
            switch (hive)
            {
                case "HKCU":
                    using (RegistryKey regKey = Registry.CurrentUser.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            Object o = regKey.GetValue(key);
                            return o;
                        }
                    }
                    break;
                case "HKLM":
                    using (RegistryKey regKey = Registry.LocalMachine.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            Object o = regKey.GetValue(key);
                            return o;
                        }
                    }
                    break;
                case "HKCR":
                    using (RegistryKey regKey = Registry.ClassesRoot.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            Object o = regKey.GetValue(key);
                            return o;
                        }
                    }
                    break;
                default:
                    throw new Exception("Invalid string format. Key must be of the form HKLM:, HKCU:, or HKCR");
            }
            return null;
        }

        private static string[] GetSubKeys(string hive, string subkey)
        {
            // subkey is gonna be in format of HKLM:\, HKCU:\, HKCR:\
            
            switch (hive)
            {
                case "HKCU":
                    using (RegistryKey regKey = Registry.CurrentUser.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            return regKey.GetSubKeyNames();
                        }
                    }
                    break;
                case "HKLM":
                    using (RegistryKey regKey = Registry.LocalMachine.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            return regKey.GetSubKeyNames();
                        }
                    }
                    break;
                case "HKCR":
                    using (RegistryKey regKey = Registry.ClassesRoot.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            return regKey.GetSubKeyNames();
                        }
                    }
                    break;
                default:
                    throw new Exception("Invalid string format. Key must be of the form HKLM:, HKCU:, or HKCR");
            }
            return null;
        }

        public override ST.Task CreateTasking()
        {
            return new ST.Task(() =>
            {
                TaskResponse resp;
                RegQueryParameters parameters = _jsonSerializer.Deserialize<RegQueryParameters>(_data.Parameters);
                List<RegQueryResult> results = new List<RegQueryResult>();
                string error = "";
                try
                {
                    string[] subkeys = GetSubKeys(parameters.Hive, parameters.Key);
                    foreach(string subkey in subkeys)
                    {
                        results.Add(new RegQueryResult
                        {
                            Name = subkey,
                            Hive = parameters.Hive,
                            ResultType = "key"
                        });
                    }
                } catch (Exception ex){ error = ex.Message; }
                try
                {
                    string[] subValNames = GetValueNames(parameters.Hive, parameters.Key);
                    foreach(string valName in subValNames)
                    {
                        RegQueryResult res = new RegQueryResult
                        {
                            Name = valName,
                            Hive = parameters.Hive,
                            ResultType = "value"
                        };
                        string resultantVal = "";
                        object tmpVal;
                        try
                        {
                            tmpVal = GetValue(parameters.Hive, parameters.Key, valName);
                        } catch (Exception ex)
                        {
                            tmpVal = ex.Message;
                        }
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
                        results.Add(res);
                    }
                } catch (Exception ex)
                {
                    error += $"\n{ex.Message}";
                }

                if (results.Count == 0)
                {
                    resp = CreateTaskResponse(error, true, "error");
                } else
                {
                    resp = CreateTaskResponse(
                        _jsonSerializer.Serialize(results.ToArray()), true);
                }

                // Your code here..
                // Then add response to queue
                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            }, _cancellationToken.Token);
        }
    }
}

#endif