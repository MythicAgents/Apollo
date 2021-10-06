using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Types.Delegates;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Classes.Core
{
    public class ChunkedFileMessageStore
    {
        private UploadMessage[] _messages = null;
        private object _lock = new object();
        private int _currentCount = 0;
        Action<byte[]> _dispatcher;

        public ChunkedFileMessageStore(Action<byte[]> dispatcher)
        {
            _dispatcher = dispatcher;
        }

        public void AddMessage(UploadMessage d)
        {
            lock(_lock)
            {
                if (_messages == null)
                {
                    _messages = new UploadMessage[d.TotalChunks];
                }
                _messages[d.ChunkNumber] = d;
                _currentCount += 1;
            }
            if (_currentCount == d.TotalChunks)
            {
                List<byte> data = new List<byte>();
                for (int i = 0; i < _messages.Length; i++)
                {
                    data.AddRange(Convert.FromBase64String(_messages[i].ChunkData));
                }
                _dispatcher.Invoke(data.ToArray());
            }
        }
    }
}
