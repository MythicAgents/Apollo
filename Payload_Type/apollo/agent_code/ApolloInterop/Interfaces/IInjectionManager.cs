using ApolloInterop.Classes.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Interfaces
{
    public interface IInjectionManager
    {
        string[] GetTechniques();
        bool SetTechnique(string technique);
        InjectionTechnique CreateInstance(byte[] code, int pid);
        InjectionTechnique CreateInstance(byte[] code, IntPtr hProcess);
        bool LoadTechnique(byte[] assembly, string name);

        Type GetCurrentTechnique();
    }
}
