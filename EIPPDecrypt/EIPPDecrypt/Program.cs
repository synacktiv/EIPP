using System;
using System.IO;
using System.Text;
using ServiceCommon.Utility;

// cp 'C:\Program Files\Azure AD Password Protection DC Agent\Rules\1.0.0.0\ServiceCommon.dll' .
// cp 'C:\Program Files\Azure AD Password Protection DC Agent\Rules\1.0.0.0\ServiceCommonHelper.dll' .
// cp 'C:\Program Files\Azure AD Password Protection DC Agent\Rules\1.0.0.0\vcruntime140.dll' .
// .\EIPPDecrypt.exe \\localhost\SYSVOL\CORP.LOCAL\AzureADPasswordProtection\Configuration\*.cfge

namespace EIPPDecrypt
{
    class EIPPDecrypt
    {
        static void Main(string[] args)
        {
            DomainEncryptor encryptor = new DomainEncryptor();
            encryptor.ServiceComponentInitialize();
            foreach (string arg in args)
                Console.WriteLine(Encoding.UTF8.GetString(encryptor.Decrypt(File.ReadAllBytes(arg))));
        }
    }

    public class DomainEncryptor
    {
        public byte[] Encrypt(byte[] bytesToEncrypt)
        {
            return this._dpapiHelper.Encrypt(bytesToEncrypt);
        }

        public byte[] Decrypt(byte[] bytesToDecrypt)
        {
            return this._dpapiHelper.Decrypt(bytesToDecrypt);
        }

        public void ServiceComponentInitialize()
        {
            this.BuildNcryptProtectionString();
            this.CreateNcryptProtectionDescriptor();
            this.GetDecryptionToken();
            this.InitializeDPAPIHelper();
        }

        private void BuildNcryptProtectionString()
        {
            LsaDnsDomainInfo lsaDnsDomainInfo = LsaPolicyDB.QueryDnsDomainInfo();
            string ncryptProtectionString = string.Format("SID={0}-516", lsaDnsDomainInfo.Sid);
            this._ncryptProtectionString = ncryptProtectionString;
        }

        private void CreateNcryptProtectionDescriptor()
        {
            IntPtr ncryptProtectionDescriptor;
            uint num = NativeMethods.NCryptCreateProtectionDescriptor(this._ncryptProtectionString, 0, out ncryptProtectionDescriptor);
            this._ncryptProtectionDescriptor = ncryptProtectionDescriptor;
        }

        private void GetDecryptionToken()
        {
            ServiceCommonHelperInterop.StaticInitialize();
            ServiceCommonHelperInterop.Instance().GetLocalSystemTokenForDecryption(out this._decryptionToken);
        }

        private void InitializeDPAPIHelper()
        {
            this._dpapiHelper = DPAPIHelper.Create(this._ncryptProtectionDescriptor, this._decryptionToken);
        }

        public DomainEncryptor()
        {
            this._ncryptProtectionString = null;
            this._ncryptProtectionDescriptor = IntPtr.Zero;
            this._decryptionToken = IntPtr.Zero;
        }

        private string _ncryptProtectionString;

        private IntPtr _ncryptProtectionDescriptor;

        private IntPtr _decryptionToken;

        private DPAPIHelper _dpapiHelper;
    }
}