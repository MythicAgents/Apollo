#define COMMAND_NAME_UPPER

#if DEBUG
#undef MKDIR
#define MKDIR
#endif

#if MKDIR

using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using Apollo.Jobs;
using Apollo.Tasks;


namespace Apollo.CommandModules
{
    public class MakeDirectory
    {
        public static void Execute(Job job, Agent agent)
        {
            Task task = job.Task;
            string path = task.parameters;
            if (Directory.Exists(path))
            {
                job.SetError($"Directory \"{path}\" already exists.");
                return;
            }

            try
            {
                var dinfo = Directory.CreateDirectory(path);
                job.Task.completed = true;
                ApolloTaskResponse resp = new ApolloTaskResponse(job.Task, $"Created directory {dinfo.FullName}")
                {
                    artifacts = new Mythic.Structs.Artifact[]
                    {
                        new Mythic.Structs.Artifact(){ base_artifact = "Directory Create", artifact=dinfo.FullName}
                    }
                };
                job.SetComplete(resp);
            }
            catch (Exception e)
            {
                job.SetError($"Error creating directory \"{path}\": {e.Message}");
            }
        }
    }
}
#endif