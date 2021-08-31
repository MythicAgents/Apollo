using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Interfaces
{
    public interface ISerializer
    {
        string Serialize(object obj);
        T Deserialize<T>(string msg);
    }
}
