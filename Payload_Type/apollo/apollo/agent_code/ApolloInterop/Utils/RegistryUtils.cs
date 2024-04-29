using Microsoft.Win32;
using System;

namespace ApolloInterop.Utils
{
    public static class RegistryUtils
    {
        public static RegistryKey GetRegistryKey(string hive, string subkey, bool forWriting)
        {
            RegistryKey regKey;
            switch (hive)
            {
                case "HKU":
                    regKey = Registry.Users.OpenSubKey(subkey, forWriting);
                    break;
                case "HKCC":
                    regKey = Registry.CurrentConfig.OpenSubKey(subkey, forWriting);
                    break;
                case "HKCU":
                    regKey = Registry.CurrentUser.OpenSubKey(subkey, forWriting);
                    break;
                case "HKLM":
                    regKey = Registry.LocalMachine.OpenSubKey(subkey, forWriting);
                    break;
                case "HKCR":
                    regKey = Registry.ClassesRoot.OpenSubKey(subkey, forWriting);
                    break;
                default:
                    throw new Exception($"Unknown registry hive: {hive}");
            }
            return regKey;
        }
    }
}
