using System;
using Microsoft.Win32;
using System.Data;

namespace Utils
{
    class RegistryUtils
    {
        
        public static object GetValue(string subkey, string key)
        {
            // subkey is gonna be in format of HKLM:\, HKCU:\, HKCR:\
            string[] parts = subkey.Split(new char[] { ':' }, 2);
            if (parts.Length != 2)
                throw new Exception("Invalid string format. Key must be of the form HKLM:, HKCU:, or HKCR");
            subkey = parts[1];
            if (subkey.IndexOf('\\') == 0 && subkey.Length > 1)
            {
                subkey = subkey.Substring(1);
            } else if (subkey.IndexOf('\\') == 0 && subkey.Length == 1)
            {
                subkey = "";
            }
            switch(parts[0].ToUpper())
            {
                case "HKCU":
                    using (RegistryKey regKey = Registry.CurrentUser.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            Object o = regKey.GetValue(key);
                            return o;
                        }
                    }
                    break;
                case "HKLM":
                    using (RegistryKey regKey = Registry.LocalMachine.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            Object o = regKey.GetValue(key);
                            return o;
                        }
                    }
                    break;
                case "HKCR":
                    using (RegistryKey regKey = Registry.ClassesRoot.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            Object o = regKey.GetValue(key);
                            return o;
                        }
                    }
                    break;
                default:
                    throw new Exception("Invalid string format. Key must be of the form HKLM:, HKCU:, or HKCR");
            }
            return null;
        }

        public static string[] GetValueNames(string subkey)
        {
            // subkey is gonna be in format of HKLM:\, HKCU:\, HKCR:\
            string[] parts = subkey.Split(new char[] { ':' }, 2);
            if (parts.Length != 2)
                throw new Exception("Invalid string format. Key must be of the form HKLM:, HKCU:, or HKCR");
            subkey = parts[1];
            if (subkey.IndexOf('\\') == 0 && subkey.Length > 1)
            {
                subkey = subkey.Substring(1);
            }
            else if (subkey.IndexOf('\\') == 0 && subkey.Length == 1)
            {
                subkey = "";
            }
            switch (parts[0].ToUpper())
            {
                case "HKCU":
                    using (RegistryKey regKey = Registry.CurrentUser.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            return regKey.GetValueNames();
                        }
                    }
                    break;
                case "HKLM":
                    using (RegistryKey regKey = Registry.LocalMachine.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            return regKey.GetValueNames();
                        }
                    }
                    break;
                case "HKCR":
                    using (RegistryKey regKey = Registry.ClassesRoot.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            return regKey.GetValueNames();
                        }
                    }
                    break;
                default:
                    throw new Exception("Invalid string format. Key must be of the form HKLM:, HKCU:, or HKCR");
            }
            return null;
        }

        public static string[] GetSubKeys(string subkey)
        {
            // subkey is gonna be in format of HKLM:\, HKCU:\, HKCR:\
            string[] parts = subkey.Split(new char[] { ':' }, 2);
            if (parts.Length != 2)
                throw new Exception("Invalid string format. Key must be of the form HKLM:, HKCU:, or HKCR");
            subkey = parts[1];
            if (subkey.IndexOf('\\') == 0 && subkey.Length > 1)
            {
                subkey = subkey.Substring(1);
            }
            else if (subkey.IndexOf('\\') == 0 && subkey.Length == 1)
            {
                subkey = "";
            }
            switch (parts[0].ToUpper())
            {
                case "HKCU":
                    using (RegistryKey regKey = Registry.CurrentUser.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            return regKey.GetSubKeyNames();
                        }
                    }
                    break;
                case "HKLM":
                    using (RegistryKey regKey = Registry.LocalMachine.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            return regKey.GetSubKeyNames();
                        }
                    }
                    break;
                case "HKCR":
                    using (RegistryKey regKey = Registry.ClassesRoot.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            return regKey.GetSubKeyNames();
                        }
                    }
                    break;
                default:
                    throw new Exception("Invalid string format. Key must be of the form HKLM:, HKCU:, or HKCR");
            }
            return null;
        }

        public static bool SetValue(string subkey, string name, object value)
        {
            bool bRet = false;
            // subkey is gonna be in format of HKLM:\, HKCU:\, HKCR:\
            string[] parts = subkey.Split(new char[] { ':' }, 2);
            if (parts.Length != 2)
                throw new Exception("Invalid string format. Key must be of the form HKLM:, HKCU:, or HKCR");
            subkey = parts[1];
            if (subkey.IndexOf('\\') == 0 && subkey.Length > 1)
            {
                subkey = subkey.Substring(1);
            }
            else if (subkey.IndexOf('\\') == 0 && subkey.Length == 1)
            {
                subkey = "";
            }
            switch (parts[0].ToUpper())
            {
                case "HKCU":
                    using (RegistryKey regKey = Registry.CurrentUser.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            regKey.SetValue(name, value);
                            bRet = true;
                        }
                    }
                    break;
                case "HKLM":
                    using (RegistryKey regKey = Registry.LocalMachine.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            regKey.SetValue(name, value);
                            bRet = true;
                        }
                    }
                    break;
                case "HKCR":
                    using (RegistryKey regKey = Registry.ClassesRoot.OpenSubKey(subkey))
                    {
                        if (regKey != null)
                        {
                            regKey.SetValue(name, value);
                            bRet = true;
                        }
                    }
                    break;
                default:
                    throw new Exception("Invalid string format. Key must be of the form HKLM:, HKCU:, or HKCR");
            }
            return bRet;
        }
    }
}
