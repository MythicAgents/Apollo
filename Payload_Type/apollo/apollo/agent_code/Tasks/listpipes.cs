#define COMMAND_NAME_UPPER

#if DEBUG
#define LISTPIPES
#endif

#if LISTPIPES

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;

namespace Tasks
{
    public class listpipes : Tasking
    {
        [DataContract]
        internal struct ListPipesParameters { }

        public listpipes(IAgent agent, MythicTask task) : base(agent, task) { }

        public override void Start()
        {
            MythicTaskResponse resp;
            try
            {
                var pipes = EnumerateNamedPipes();
                string output = pipes.Count == 0
                    ? "No named pipes found."
                    : $"Found {pipes.Count} named pipes:\n" + string.Join("\n", pipes);

                resp = CreateTaskResponse(output, true, "completed");
            }
            catch (Exception ex)
            {
                resp = CreateTaskResponse($"Exception in listpipes: {ex.Message}\n{ex.StackTrace}", true, "error");
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }

        private List<string> EnumerateNamedPipes()
        {
            var pipeList = new List<string>();

            WIN32_FIND_DATA findData;
            IntPtr handle = FindFirstFileW(@"\\.\pipe\*", out findData);
            if (handle == INVALID_HANDLE_VALUE)
            {
                throw new Exception($"FindFirstFileW failed with error {Marshal.GetLastWin32Error()}");
            }

            try
            {
                do
                {
                    string name = findData.cFileName?.TrimEnd('\0');
                    if (!string.IsNullOrEmpty(name))
                    {
                        pipeList.Add(name);
                    }
                } while (FindNextFileW(handle, out findData));
            }
            finally
            {
                FindClose(handle);
            }

            return pipeList;
        }

        private const int MAX_PATH = 260;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WIN32_FIND_DATA
        {
            public uint dwFileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint dwReserved0;
            public uint dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
            public string cAlternateFileName;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr FindFirstFileW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpFileName,
            out WIN32_FIND_DATA lpFindFileData);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool FindNextFileW(IntPtr hFindFile, out WIN32_FIND_DATA lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool FindClose(IntPtr hFindFile);
    }
}
#endif