using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Apollo.CommandModules;
using Apollo.Tasks;

namespace Apollo.MessageInbox
{

    public delegate object SenderFunction(object arg);
    public class Envelope
    {
        public string EnvelopeGUID;
        private SenderFunction sendFunc;
        private object Contents;
        internal Task task;
        public Envelope(SenderFunction func, object args, Task taskObj)
        {
            EnvelopeGUID = Guid.NewGuid().ToString();
            sendFunc = func;
            Contents = args;
            task = taskObj;
        }

        public bool Send()
        {
            object results = null;
            try
            {
                results = sendFunc(Contents);
                Inbox.AddMessage(task.id, results);
            }
            catch (Exception ex)
            {
                // return false;
                throw ex;
            }
            return true;
        }
    }
}
