using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Tasks
{
    public class keylog : Tasking
    {
        public keylog(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
        {
        }

        public override void Kill()
        {
            base.Kill();
        }

        public override Task CreateTasking()
        {
            throw new NotImplementedException();
        }
    }
}
