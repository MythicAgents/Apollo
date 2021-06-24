using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Reflection;

namespace Utils
{
    public static class ReflectionUtils
    {
        internal static Type[] GetTypesInNamespace(Assembly assembly, string nameSpace)
        {
            return
                assembly.GetTypes()
                        .Where(t => String.Equals(t.Namespace, nameSpace, StringComparison.Ordinal))
                        .ToArray();
        }

    }
}
