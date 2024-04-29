using ApolloInterop.Interfaces;
using System;

namespace ApolloInterop.Classes.Events
{
    public class ChunkMessageEventArgs<T> : EventArgs where T : IChunkMessage
    {
        public T[] Chunks;

        public ChunkMessageEventArgs(T[] chunks)
        {
            Chunks = chunks;
        }
    }
}
