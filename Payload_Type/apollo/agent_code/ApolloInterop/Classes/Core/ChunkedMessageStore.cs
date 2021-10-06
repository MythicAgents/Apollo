using ApolloInterop.Classes.Events;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Types.Delegates;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Classes.Core
{
    public class ChunkedMessageStore<T> where T : IChunkMessage
    {
        private T[] _messages = null;
        private object _lock = new object();
        private int _currentCount = 0;

        public event EventHandler<ChunkMessageEventArgs<T>> MessageComplete;
        public void OnMessageComplete() => MessageComplete?.Invoke(this, new ChunkMessageEventArgs<T>(_messages));
        public void AddMessage(T d)
        {
            lock(_lock)
            {
                if (_messages == null)
                {
                    _messages = new T[d.GetTotalChunks()];
                }
                _messages[d.GetChunkNumber()] = d;
                _currentCount += 1;
            }
            if (_currentCount == d.GetTotalChunks())
            {
                OnMessageComplete();
            }
        }
    }
}
