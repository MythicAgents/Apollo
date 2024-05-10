using System;

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
