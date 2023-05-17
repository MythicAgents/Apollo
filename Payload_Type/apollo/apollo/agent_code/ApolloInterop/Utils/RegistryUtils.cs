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
                    regKey = Registry.Users.OpenSubKey(subkey, true);
                    break;
                case "HKCC":
                    regKey = Registry.CurrentConfig.OpenSubKey(subkey, true);
                    break;
                case "HKCU":
                    regKey = Registry.CurrentUser.OpenSubKey(subkey, true);
                    break;
                case "HKLM":
                    regKey = Registry.LocalMachine.OpenSubKey(subkey, true);
                    break;
                case "HKCR":
                    regKey = Registry.ClassesRoot.OpenSubKey(subkey, true);
                    break;
                default:
                    throw new Exception($"Unknown registry hive: {hive}");
            }
            return regKey;
        }
    }
}
