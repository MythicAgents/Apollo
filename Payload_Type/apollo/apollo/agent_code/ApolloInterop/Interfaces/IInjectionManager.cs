using ApolloInterop.Classes.Core;
using System;

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
