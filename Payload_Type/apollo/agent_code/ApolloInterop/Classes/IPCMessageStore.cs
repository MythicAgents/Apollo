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
        private IPCData[] _data = null;
        private int _currentCount = 0;
        DispatchMessage _dispatcher;

        public IPCMessageStore(DispatchMessage dispatcher)
        {
            _dispatcher = dispatcher;
        }

        public void AddMessage(byte[] b)
        {
            lock(_lock)
            {

            }
        }

        public void AddMessage(IPCData d)
        {
            lock(_lock)
            {
                if (_data == null)
                {
                    _data = new IPCData[d.TotalChunks];
                }
                _data[d.ChunkNumber] = d;
                _currentCount += 1;
            }
            if (_currentCount == d.TotalChunks)
            {
                int szData = _data.Sum(packet => packet.DataLength);
                byte[] data = new byte[szData];
                int curOffset = 0;
                for(int i = 0; i < _data.Length; i++)
                {
                    Buffer.BlockCopy(_data[i].Data, 0, data, curOffset, _data[i].DataLength);
                    curOffset += _data[i].DataLength;
                }
                _dispatcher(data, _data[0].Message);
            }
        }
    }
}
