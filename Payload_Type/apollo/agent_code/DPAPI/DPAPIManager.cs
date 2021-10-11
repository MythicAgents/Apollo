using ApolloInterop.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DPAPI
{
    public class DPAPIManager
    {
        private IAgent _agent;
        public DPAPIManager(IAgent agent)
        {
            _agent = agent;
        }


    }
}
