// See https://aka.ms/new-console-template for more information
using static System.Net.Mime.MediaTypeNames;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

string uedclutil = "018";
string uedclcustref = "ALO20191223";
string uedclphone = "256771843614";
string uedcltrantype = "New Connection";
string uedclusername = "ebankitapp";
string uedclpass = "D7@n0!@80o2";
string text = uedclutil + uedclcustref + uedclphone + uedcltrantype + uedclusername + uedclpass;
//string text = "018ALO20191223256771843614New ConnectionebankitappD7@n0!@80o2";
string umemecertcn = "agentbankingtransintuat.dfcugroup.com";

byte[] data = System.Text.Encoding.ASCII.GetBytes(text);
X509Store my = new X509Store(StoreName.My, StoreLocation.LocalMachine);
my.Open(OpenFlags.ReadOnly);
RSACng csp = null;
RSA cspx = null;
foreach (X509Certificate2 cert in my.Certificates)
{
    if (cert.Subject.Contains(umemecertcn))//ezeelink.mobile-money.com//"CN=dfcubank"
    {
        //GlobalWebAPI.WriteLog(string.Concat("Encryption Entered2->", cert.SubjectName.ToString()));
        if (cert.HasPrivateKey == true)
        {
            cspx = cert.GetRSAPrivateKey();
            break;
        }
        else
        {
            throw new Exception("Private Key Not Found!");
        }
    }
}
if (cspx == null)
{
    throw new Exception("Certificate Not Found!");
}
string strConvertedSignature = null;
strConvertedSignature = Convert.ToBase64String(cspx.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

Console.WriteLine(strConvertedSignature);

// Signature Verification
string originalData = text;
///string signature = "CGjoTi4WlqPEGKxHzBKOa3kASM+h8c3EmFk4+bNVU9s9f8nsJqAxls1NKprch5VrXqsVDAZO7MDbBmRy02LVjcEPd9Szx7RaK0QQBv/5w99ujNPIjXHRU3nSmunAWcCdZ+yAxv/IPT5LcsendSWSa+SwFTWcpqae6io/k/+WP9faBE3f7q93UI+TcQCHVdcHY3my8TQnuAjVrDfL0gJkbK79N4T7LeyT0VL8UsJBVyPVJGSHKIyzO1jG5/AMeJUkHfLT3ed2N+u1B+w7kafUjSJq+cVMMLuiPQMrcWNVvpAK3dBXAtSx/F79aVU/6ZQbe8LFHZH/C2He8ObXjrx9QQ==";
string signature = strConvertedSignature;
//string ur = null;
bool certexist = false;
//string umemecertcn = GetAPPCertcn(ur);

if (umemecertcn == "")
{
    certexist = false;
}
else if (umemecertcn != "")
{
    //GlobalWebAPI.WriteLog(string.Concat("Public cert Subject Found-->", umemecertcn));
    //string umemecertcn = System.Configuration.ConfigurationManager.AppSettings["Umemecertcn"];

    foreach (X509Certificate2 cert in my.Certificates)
    {
        if (cert.Subject.Contains(umemecertcn)) //"CN=dfcubank"
        {
            csp = (RSACng)cert.PublicKey.Key;
            //GlobalWebAPI.WriteLog(string.Concat("Data Decryption Passed31->", "Public-Key Found"));
            break;
        }
    }

    if (csp == null)
    {
        certexist = false;
        //GlobalWebAPI.WriteLog(string.Concat("Data Decryption Passed32->", "Certificate not Found"));
        throw new Exception("Certificate Not Found!");
    }
    else
    {
        //GlobalWebAPI.WriteLog(string.Concat("Sign Verification Started 1->", "Public-Key Found"));
        try
        {
            //// Hash the data
            //SHA1Managed sha1 = new SHA1Managed();
            //UnicodeEncoding encoding = new UnicodeEncoding();

            byte[] originalByte = System.Text.Encoding.ASCII.GetBytes(originalData);
            byte[] signatureByte = Convert.FromBase64String(signature);

            ////byte[] data = encoding.GetBytes(text);
            //byte[] hash = sha1.ComputeHash(originalByte);

            //// Verify the signature with the hash
            //certexist = csp.VerifyHash(hash, CryptoConfig.MapNameToOID("SHA1"), signatureByte);

            certexist = csp.VerifyData(originalByte, signatureByte, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            //return csp.VerifyData(originalByte, new SHA256CryptoServiceProvider(), signatureByte);
            //GlobalWebAPI.WriteLog(string.Concat("Sign Verification Passed 3-->", certexist));
            Console.WriteLine(certexist);

        }
        catch (Exception ex)
        {
            //GlobalWebAPI.WriteLog(string.Concat("Sign Verification Failed 1-->", ex.Message));
        }
    }
}
