#define COMMAND_NAME_UPPER

#if DEBUG
#undef RM
#define RM
#endif

#if RM
using Apollo.Jobs;
using System;
using Apollo.Tasks;
using Newtonsoft.Json;
using System.IO;

namespace Apollo.CommandModules
{
    public class Remove
    {
        public struct RemoveArguments
        {
            public string host;
            public string path;
        }

        public static void Execute(Job job, Agent implant)
        {
            Task task = job.Task;
            RemoveArguments args = JsonConvert.DeserializeObject<RemoveArguments>(task.parameters);
            string path = args.path;
            if (!string.IsNullOrEmpty(args.host))
            {
                path = $"\\\\{args.host}\\{path.Replace(":", "$")}";
            }
            ApolloTaskResponse resp;
            switch (job.Task.command)
            {
                case "rm":
                    try
                    {
                        FileInfo finfo = new FileInfo(path);
                        System.IO.File.Delete(path);
                        task.completed = true;
                        resp = new ApolloTaskResponse(task, $"Successfully deleted file \"{path}\"");
                        resp.removed_files = new Mythic.Structs.RemovedFileInformation[]
                        {
                            new Mythic.Structs.RemovedFileInformation(){ host=args.host, path=finfo.FullName},
                        };
                        resp.artifacts = new Mythic.Structs.Artifact[]
                        {
                            new Mythic.Structs.Artifact(){ artifact=$"{finfo.FullName}", base_artifact="File Delete"}
                        };
                        job.SetComplete(resp);
                    }
                    catch (Exception e)
                    {
                        job.SetError($"Error removing file \"{path}\": {e.Message}");
                    }
                    break;
                case "rmdir":
                    try
                    {
                        DirectoryInfo dirinfo = new DirectoryInfo(path);
                        System.IO.Directory.Delete(path);
                        task.completed = true;
                        resp = new ApolloTaskResponse(task, $"Successfully deleted file \"{path}\"");
                        resp.removed_files = new Mythic.Structs.RemovedFileInformation[]
                        {
                            new Mythic.Structs.RemovedFileInformation(){ host=args.host, path=dirinfo.FullName}
                        };
                        resp.artifacts = new Mythic.Structs.Artifact[]
                        {
                            new Mythic.Structs.Artifact(){ artifact=$"{dirinfo.FullName}", base_artifact="Directory Delete"}
                        };
                        job.SetComplete(resp);
                    } catch (Exception ex)
                    {
                        job.SetError($"Error deleting file \"{path}\". Reason: {ex.Message}");
                    }
                    break;
                default:
                    job.SetError("Unsupported code path reached in Remove.cs");
                    break;
            }
        }
    }
}
#endif