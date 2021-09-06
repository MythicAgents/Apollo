using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PSKCryptography;

namespace EKECryptography
{
    public class EKECryptographyProvider : PSKCryptographyProvider
    {
        public EKECryptographyProvider(string uuid, string psk) : base(uuid, psk)
        {

        }

        public override bool UpdateKey(string key)
        {
            this.PSK = Convert.FromBase64String(key);
            return true;
        }
    }
}
