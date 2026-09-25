#define NAMED_PIPE
using System;
using System.IO.Pipes;
using System.IO;
using static ExecutePE.Internals.NativeDeclarations;
using System.Threading.Tasks;
using System.Threading;
using ApolloInterop.Classes.Events;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ExecutePE.Helpers
{

    class StdHandleRedirector : IDisposable
    {
        NamedPipeServerStream stdoutServerStream;
        NamedPipeClientStream stdoutClientStream;

        FileStream stdoutReader;

        private IntPtr _oldStdout;
        private IntPtr _oldStderr;
        private int _osfHandle;
        private int _oldOsfOut;
        private int _oldOsfErr;
        IntPtr _stdoutClientHandle;
        private Encoding _oldEncoding;

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
            SetupNamePipes();
            DuplicateHandlesAndEncoding();
            SetupRedirection();
        }

        private void DuplicateHandlesAndEncoding() {
            _oldEncoding = (Encoding)Console.OutputEncoding.Clone();
            DuplicateHandle(
                GetCurrentProcess(),
                GetStdHandle(StdHandle.Stdout),
                GetCurrentProcess(),
                out _oldStdout,
                0,
                false,
                DuplicateOptions.DuplicateSameAccess
            );
            DuplicateHandle(
                GetCurrentProcess(),
                GetStdHandle(StdHandle.Stderr),
                GetCurrentProcess(),
                out _oldStderr,
                0,
                false,
                DuplicateOptions.DuplicateSameAccess
            );

            IntPtr pipeWriteHandle = stdoutClientStream.SafePipeHandle.DangerousGetHandle();
            DuplicateHandle(
                GetCurrentProcess(),
                pipeWriteHandle,
                GetCurrentProcess(),
                out _stdoutClientHandle,
                0,
                false,
                DuplicateOptions.DuplicateSameAccess
            );

            _oldOsfOut = _dup(1);
            _oldOsfErr = _dup(2);
        }
        
        private void SetupNamePipes() {
            string stdoutGuid = Guid.NewGuid().ToString();
            stdoutServerStream = new NamedPipeServerStream(stdoutGuid, PipeDirection.InOut, 100, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            stdoutServerStream.BeginWaitForConnection(new AsyncCallback(stdoutServerStream.EndWaitForConnection), stdoutServerStream);

            stdoutClientStream = new NamedPipeClientStream("127.0.0.1", stdoutGuid, PipeDirection.InOut, PipeOptions.Asynchronous);
            stdoutClientStream.Connect();
        }

        private void SetupRedirection()
        {
            var stdoutServerFileHandle = new SafeFileHandle(
                stdoutServerStream.SafePipeHandle.DangerousGetHandle(),
                ownsHandle: false
            );
            stdoutReader = new FileStream(stdoutServerFileHandle, FileAccess.Read);

            SetStdHandle(StdHandle.Stdout, _stdoutClientHandle);
            SetStdHandle(StdHandle.Stderr, _stdoutClientHandle);

            _osfHandle = _open_osfhandle(_stdoutClientHandle.ToInt32(), _O_TEXT);
            if (_osfHandle == 0)
                throw new Exception("_open_osfhandle failed");

            if (_dup2(_osfHandle, 1) != 0)
                throw new Exception("_dup2 stdout failed");

            if (_dup2(_osfHandle, 2) != 0)
                throw new Exception("_dup2 stderr failed");
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
            } while (!_cts.IsCancellationRequested || n > 0);
            
            //do
            //{
            //    tmp = new byte[szBuf];
            //    n = stream.Read(tmp, 0, szBuf);
            //        if (n > 0)
            //        {
            //            newstr = new byte[n];
            //            Array.Copy(tmp, newstr, n);
            //            eventhandler?.Invoke(this, new StringDataEventArgs(Console.OutputEncoding.GetString(newstr)));
            //    }
            //    else
            //    {
            //        break;
            //    }
            //} while (n > 0);
        }

        private void ReadStdoutAsync()
        {
            ReadFileStreamAsync(stdoutReader, _stdoutHandler);
        }

        public void Dispose()
        {
            Console.Out.Flush();
            Console.Error.Flush();
            fflush(IntPtr.Zero);
            stdoutClientStream.Flush();
            stdoutServerStream.Flush();

            if (_dup2(_oldOsfOut, 1) != 0)
                throw new Exception("_dup2 stdout failed");

            if (_dup2(_oldOsfErr, 2) != 0)
                throw new Exception("_dup2 stderr failed");

            SetStdHandle(StdHandle.Stderr, _oldStderr);
            SetStdHandle(StdHandle.Stdout, _oldStdout);
            Console.SetOut(new StreamWriter(Console.OpenStandardOutput(), _oldEncoding)
            {
                AutoFlush = true
            });

            Console.SetError(new StreamWriter(Console.OpenStandardError(), _oldEncoding)
            {
                AutoFlush = true
            });
            _close(_oldOsfOut);
            _close(_oldOsfErr);
            _close(_osfHandle);
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