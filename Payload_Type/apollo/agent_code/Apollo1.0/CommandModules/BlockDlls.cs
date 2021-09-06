#define COMMAND_NAME_UPPER

#if DEBUG
#undef BLOCKDLLS
#define BLOCKDLLS
#endif

#if BLOCKDLLS
using System;
using System.Linq;
using System.Text;
using Apollo.Jobs;
using Apollo.Tasks;
using Apollo.Evasion;
using Newtonsoft.Json;

namespace Apollo.CommandModules
{
    class BlockDlls
    {

        public struct BlockDllArgs
        {
            public bool block;
        }

        /// <summary>
        /// Change the sacrificial process that's spawned for certain post-exploitation jobs
        /// such as execute assembly. Valid taskings are spawnto_x64 and spawnto_x86. If the
        /// file does not exist or the file is not of an executable file type, the job
        /// will return an error message.
        /// </summary>
        /// <param name="job">Job associated with this task. The filepath is specified by job.Task.parameters.</param>
        /// <param name="agent">Agent this task is run on.</param>
        /// 
        public static void Execute(Job job, Agent agent)
        {
            Task task = job.Task;
            BlockDllArgs args = JsonConvert.DeserializeObject<BlockDllArgs>(job.Task.parameters);

            if (EvasionManager.BlockDlls(args.block))
            {
                if (args.block)
                {
                    job.SetComplete($"Blocking non-Microsoft-signed DLLs.");
                } else
                {
                    job.SetComplete("All DLLs can be loaded into post-ex processes.");
                }
            }
            else
            {
                job.SetError($"Failed to set block DLLs.");
            }
        }
    }
}
#endif