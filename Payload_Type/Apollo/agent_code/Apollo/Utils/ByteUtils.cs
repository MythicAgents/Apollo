using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Utils
{
    class ByteUtils
    {
        public static bool ByteSequenceEquals(byte[] a1, byte[] a2)
        {
            if (a1 == null || a2 == null)
                return false;
            int min = Math.Min(a1.Length, a2.Length);

            for(int i = 0; i < min; i++)
            {
                if (a1[i] != a2[i])
                    return false;
            }

            return true;
        }
    }
}
