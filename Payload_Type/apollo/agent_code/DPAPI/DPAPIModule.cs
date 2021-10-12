using ApolloInterop.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DPAPI
{
    public class DPAPIModule
    {
        private static byte[] _entropy =
        {
            77,
            97,
            121,
            108,
            108,
            97,
            114,
            116,
        };
        private static int _cryptProtectLocalMachine = 0x4;
        private IAgent _agent;
        public DPAPIModule(IAgent agent)
        {
            _agent = agent;
        }


    }
}
