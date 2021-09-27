using ApolloInterop.Enums.ApolloEnums;
using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Types.Delegates;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Classes
{
    public class IPCMessageStore
    {
        private object _lock = new object();
        private IPCChunkedData[] _data = null;
        private int _currentCount = 0;
        DispatchMessage _dispatcher;

        public IPCMessageStore(DispatchMessage dispatcher)
        {
            _dispatcher = dispatcher;
        }

        public void AddMessage(IPCChunkedData d)
        {
            lock(_lock)
            {
                if (_data == null)
                {
                    _data = new IPCChunkedData[d.TotalChunks];
                }
                _data[d.ChunkNumber] = d;
                _currentCount += 1;
            }
            if (_currentCount == d.TotalChunks)
            {
                List<byte> data = new List<byte>();
                for(int i = 0; i < _data.Length; i++)
                {
                    data.AddRange(Convert.FromBase64String(_data[i].Data));
                }
                _dispatcher(data.ToArray(), _data[0].Message);
            }
        }
    }
}
