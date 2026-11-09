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

        private static string FormatValue(object value)
        {
            if (value == null)
                return "(value not set)";
            if (value is byte[] bytes)
                return BitConverter.ToString(bytes);
            if (value is string[] strings)
                return string.Join("\n", strings);
            return value.ToString();
        }


        public override void Start()
        {
            RegQueryParameters parameters = _jsonSerializer.Deserialize<RegQueryParameters>(_data.Parameters);
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
                string[] subkeys = GetSubKeys(parameters.Hive, parameters.Key);
                customBrowserEntry.Success = true;
                artifacts.Add(Artifact.RegistryRead(parameters.Hive, parameters.Key));
                foreach (string subkey in subkeys)
                {
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
                    try
                    {
                        tmpVal = GetValue(parameters.Hive, parameters.Key, valName);
                    }
                    catch (Exception ex)
                    {
                        tmpVal = ex.Message;
                    }

                    string value = FormatValue(tmpVal);
                    string valueType = GetType(parameters.Hive, parameters.Key, valName);
                    customBrowserEntry.Children.Add(new CustomBrowserEntryChild
                    {
                        CanHaveChildren = false,
                        Name = valName == "" ? "(Default)" : valName,
                        Metadata = new Dictionary<string, object>
                        {
                            { "type", valueType },
                            { "value", value },
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
            artifacts.Add(customBrowser);
            bool failed = customBrowserEntry.Children.Count == 0 && !string.IsNullOrWhiteSpace(error);
            _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                failed ? error : "",
                true,
                failed ? "error" : "completed",
                artifacts.ToArray()));

        }
    }
}

#endif