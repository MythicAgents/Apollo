using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Utils
{
    public static class PathUtils
    {
        public static string GetPublicPath()
        {
            if (StringUtils.StringIsSet(Environment.GetEnvironmentVariable("HOMEDRIVE")))
                return Environment.GetEnvironmentVariable("HOMEDRIVE") + "\\Users\\Public\\";
            else
                return "C:\\Users\\Public\\";
        }
    }
}
