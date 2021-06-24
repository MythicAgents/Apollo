using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPC
{
    public enum JobExitCode
    {
        Ok = 0,
        PipeStartError,
        AssemblyReadError
    }
}
