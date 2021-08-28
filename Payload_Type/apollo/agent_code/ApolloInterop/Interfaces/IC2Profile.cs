using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Interfaces
{
    public interface IC2Profile
    {
        string RegisterCallback(string uuid);
        
        // should be a mythic messages
        object GetMessages();

        void PostResponses();

        void GetFiles();
    }
}
