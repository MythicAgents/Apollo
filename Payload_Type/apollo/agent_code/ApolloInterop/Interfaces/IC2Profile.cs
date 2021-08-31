using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Structs.MythicStructs;
namespace ApolloInterop.Interfaces
{
    public interface IC2Profile
    {
        bool RegisterCallback(CheckinMessage checkinMessage, out string newUUID);
        
        bool GetMessages(TaskingMessage msg, out MessageResponse resp);
    
    }
}
