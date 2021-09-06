using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AI = ApolloInterop;
using ApolloInterop.Interfaces;
namespace Apollo.Management.Socks
{
    public class SocksManager : AI.Classes.SocksManager
    {
        public SocksManager(IAgent agent) : base(agent)
        {

        }
    }
}
