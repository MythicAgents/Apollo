#define COMMAND_NAME_UPPER

#if DEBUG
#undef GET_CURRENT_INJECTION_TECHNIQUE
#undef SET_INJECTION_TECHNIQUE
#undef LIST_INJECTION_TECHNIQUES
#define GET_CURRENT_INJECTION_TECHNIQUE
#define SET_INJECTION_TECHNIQUE
#define LIST_INJECTION_TECHNIQUES
#endif

#if GET_CURRENT_INJECTION_TECHNIQUE || SET_INJECTION_TECHNIQUE || LIST_INJECTION_TECHNIQUES

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Reflection = System.Reflection;
using Apollo.Jobs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.IO.Pipes;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization;
using System.IO;
using IPC;

namespace Apollo.CommandModules
{
    class InjectionManager
    {
        public static void Execute(Job job, Agent implant)
        {
            switch (job.Task.command)
            {
#if SET_INJECTION_TECHNIQUE
                case "set_injection_technique":
                    SetInjectionTechnique(job, implant);
                    break;
#endif
#if GET_CURRENT_INJECTION_TECHNIQUE
                case "get_current_injection_technique":
                    GetCurrentInjectionTechnique(job, implant);
                    break;
#endif
#if LIST_INJECTION_TECHNIQUES
                case "list_injection_techniques":
                    ListInjectionTechniques(job, implant);
                    break;
#endif
                default:
                    job.SetError($"Unknown command \"{job.Task.command}\"");
                    break;
            }
        }
#if SET_INJECTION_TECHNIQUE
        private static void SetInjectionTechnique(Job job, Agent implant)
        {
            if (Injection.InjectionTechnique.SetInjectionTechnique(job.Task.parameters))
            {
                job.SetComplete($"Set global injection technique to {Injection.InjectionTechnique.GetInjectionTechnique().Name}");
            } else
            {
                job.SetError($"Could not set injection technique to {job.Task.parameters}");
            }
        }
#endif
#if GET_CURRENT_INJECTION_TECHNIQUE
        private static void GetCurrentInjectionTechnique(Job job, Agent implant)
        {
            job.SetComplete($"Current injection technique set to: {Injection.InjectionTechnique.GetInjectionTechnique().Name}");
        }
#endif
#if LIST_INJECTION_TECHNIQUES
        private static void ListInjectionTechniques(Job job, Agent implant)
        {
            string[] techniqueNames = Injection.InjectionTechnique.GetLoadedInjectionTechniques();
            string resultString = "Currently loaded injection techniques:";
            foreach(string tech in techniqueNames)
            {
                resultString += $"\n\t{tech}";
            }
            job.SetComplete(resultString);
        }
    }
}
#endif
#endif