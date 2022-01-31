using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Classes.Events
{
    public class StringDataEventArgs : EventArgs
    {
        public string Data;

        public StringDataEventArgs(string d)
        {
            Data = d;
        }
    }
}
