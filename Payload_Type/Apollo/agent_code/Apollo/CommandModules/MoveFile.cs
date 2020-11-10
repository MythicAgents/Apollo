#define COMMAND_NAME_UPPER

#if DEBUG
#undef MV
#define MV
#endif


#if MV
using Newtonsoft.Json;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using Mythic.Structs;
using Apollo.Jobs;
using Apollo.MessageInbox;
using Apollo.Tasks;
using Apollo.Utils;

namespace Apollo.CommandModules
{
    public struct MoveParameters
    {
        public string source;
        public string destination;
    }

    public class MoveFile
    {
        public static void Execute(Job job, Agent implant)
        {
            Task task = job.Task;

            MoveParameters arguments = JsonConvert.DeserializeObject<MoveParameters>(task.parameters);
            if (string.IsNullOrEmpty(arguments.source))
            {
                job.SetError("No source path given to move.");
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
            FileInfo source = new FileInfo(arguments.source);
            FileInfo dest;
            try
            {
                File.Move(arguments.source, arguments.destination);
                dest = new FileInfo(arguments.destination);
                job.Task.completed = true;
                ApolloTaskResponse resp = new ApolloTaskResponse(job.Task, $"Successfully moved \"{arguments.source}\" to \"{arguments.destination}\"")
                {
                    artifacts = new Artifact[]
                    {
                        new Artifact(){base_artifact="File Move", artifact=$"Renamed {source.FullName} to {dest.FullName} (MD5: {FileUtils.GetFileMD5(dest.FullName)})"}
                    }
                };
                job.SetComplete(resp);
            } catch(Exception ex)
            {
                job.SetError($"Error performing the move operation. Reason: {ex.Message}");
            }
        }
    }
}
#endif