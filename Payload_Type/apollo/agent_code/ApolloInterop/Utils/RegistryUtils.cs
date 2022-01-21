using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Utils
{
    public static class RegistryUtils
    {
        public static RegistryKey GetRegistryKey(string hive, string subkey)
        {
            RegistryKey regKey;
            switch (hive)
            {
                case "HKU":
                    regKey = Registry.Users.OpenSubKey(subkey);
                    break;
                case "HKCC":
                    regKey = Registry.CurrentConfig.OpenSubKey(subkey);
                    break;
                case "HKCU":
                    regKey = Registry.CurrentUser.OpenSubKey(subkey);
                    break;
                case "HKLM":
                    regKey = Registry.LocalMachine.OpenSubKey(subkey);
                    break;
                case "HKCR":
                    regKey = Registry.ClassesRoot.OpenSubKey(subkey);
                    break;
                default:
                    throw new Exception($"Unknown registry hive: {hive}");
            }
            return regKey;
        }
    }
}
