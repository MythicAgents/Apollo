using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Utils
{
    class StringUtils
    {
        internal static string[] SplitCommandLine(string commandLine)
        {
            bool inQuotes = false;

            string cmdline = commandLine.Trim();
            List<string> cmds = new List<string>();
            string curCmd = "";
            for (int i = 0; i < cmdline.Length; i++)
            {
                char c = cmdline[i];
                if (c == '\"' || c == '\'')
                    inQuotes = !inQuotes;
                if (!inQuotes && c == ' ')
                {
                    cmds.Add(curCmd);
                    curCmd = "";
                }
                else
                {
                    curCmd += c;
                }
            }
            if (!string.IsNullOrEmpty(curCmd))
                cmds.Add(curCmd);
            string[] results = cmds.ToArray();
            for (int i = 0; i < results.Length; i++)
            {
                if (results[i].Length > 2)
                {
                    if (results[i][0] == '\"' && results[i][results[i].Length - 1] == '\"')
                        results[i] = results[i].Substring(1, results[i].Length - 2);
                    else if (results[i][0] == '\'' && results[i][results[i].Length - 1] == '\'')
                        results[i] = results[i].Substring(1, results[i].Length - 1);
                }
            }
            return results;
        }

        public static string FormatTimespan(TimeSpan ts)
        {
            return string.Format("{0:00}.{1:00}s", ts.Seconds, ts.Milliseconds / 10);
        }

        public static bool StringIsSet(string test)
        {
            return (test != null && test != "");
        }

        public static string Utf16ToUtf8(string utf16String)
        {
            /**************************************************************
             * Every .NET string will store text with the UTF16 encoding, *
             * known as Encoding.Unicode. Other encodings may exist as    *
             * Byte-Array or incorrectly stored with the UTF16 encoding.  *
             *                                                            *
             * UTF8 = 1 bytes per char                                    *
             *    ["100" for the ansi 'd']                                *
             *    ["206" and "186" for the russian 'κ']                   *
             *                                                            *
             * UTF16 = 2 bytes per char                                   *
             *    ["100, 0" for the ansi 'd']                             *
             *    ["186, 3" for the russian 'κ']                          *
             *                                                            *
             * UTF8 inside UTF16                                          *
             *    ["100, 0" for the ansi 'd']                             *
             *    ["206, 0" and "186, 0" for the russian 'κ']             *
             *                                                            *
             * We can use the convert encoding function to convert an     *
             * UTF16 Byte-Array to an UTF8 Byte-Array. When we use UTF8   *
             * encoding to string method now, we will get a UTF16 string. *
             *                                                            *
             * So we imitate UTF16 by filling the second byte of a char   *
             * with a 0 byte (binary 0) while creating the string.        *
             **************************************************************/

            // Storage for the UTF8 string
            string utf8String = String.Empty;

            // Get UTF16 bytes and convert UTF16 bytes to UTF8 bytes
            byte[] utf16Bytes = Encoding.Unicode.GetBytes(utf16String);
            byte[] utf8Bytes = Encoding.Convert(Encoding.Unicode, Encoding.UTF8, utf16Bytes);

            // Fill UTF8 bytes inside UTF8 string
            for (int i = 0; i < utf8Bytes.Length; i++)
            {
                // Because char always saves 2 bytes, fill char with 0
                byte[] utf8Container = new byte[2] { utf8Bytes[i], 0 };
                utf8String += BitConverter.ToChar(utf8Container, 0);
            }

            // Return UTF8
            return utf8String;
        }

    }
}
