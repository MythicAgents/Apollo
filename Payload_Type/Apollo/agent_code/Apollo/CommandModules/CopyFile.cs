#define COMMAND_NAME_UPPER

#if DEBUG
#undef CP
#define CP
#endif

#if CP
using Apollo.Jobs;
using System;
using Apollo.Tasks;
using System.Security.Principal;
using Apollo.Credentials;
using Newtonsoft.Json;
using System.IO;

namespace Apollo.CommandModules
{
    public class CopyFile
    {
        public struct CopyParameters
        {
            public string source;
            public string destination;
        }
        public static void Execute(Job job, Agent implant)
        {
            Task task = job.Task;
            CopyParameters arguments = JsonConvert.DeserializeObject<CopyParameters>(task.parameters);
            if (string.IsNullOrEmpty(arguments.source))
            {
                job.SetError("No source file given to copy.");
                return;
            }
            if (string.IsNullOrEmpty(arguments.destination))
            {
                job.SetError("No destination path was given.");
                return;
            }

            if (!File.Exists(arguments.source))
            {
                job.SetError($"File \"{arguments.source}\" does not exist.");
                return;
            }

            if (File.Exists(arguments.destination))
            {
                job.SetError($"File \"{arguments.destination}\" already exists. Delete or move this file before overwriting it.");
                return;
            }

            try
            {
                File.Copy(arguments.source, arguments.destination);
                job.SetComplete($"Successfully copied \"{arguments.source}\" to \"{arguments.destination}\"");
            }
            catch (Exception ex)
            {
                job.SetError($"Error performing the copy operation. Reason: {ex.Message}");
            }
        }
    }
}
#endif