using System;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ProsExari_Professional
{
    public class StargateJWTValidator
    {
        public void validate(String token, string requestBody, X509Certificate2Collection trustStore, Boolean ignorePayloadValidation)
        {
            X509Certificate2 cert = extractCertFromJWT(token);
            validateTrustedCertificate(trustStore, cert);
            string payload = getPayload(token);
            Byte[] publicKey = cert.GetPublicKey();

            X509SecurityKey securityKey = new X509SecurityKey(cert);
            try
            {
                JwtSecurityToken sectoken = ValidateTokenAndSetIdentity(token, securityKey);
                if (!ignorePayloadValidation) validatePayloadHash(requestBody, payload);
            }
            catch (Exception e)
            {
                throw new Exception(e.Message + "\n" + token);
            }
        }
        private void validatePayloadHash(string requestBody, string payload)
        {
            string hexstr = GetSha256FromString(requestBody);
            if (!(String.IsNullOrEmpty(payload) && String.IsNullOrEmpty(hexstr)))
            {
                if (!hexstr.Equals(payload))
                { // Compare hash of payload to payloadhash from JWT 
                    throw new StargateJWTException("Payload validation failure - 'payloadhash' JWT claim (" + payload + ")is not equal to the hash of the request body (" + requestBody + ")");
                }
            }
        }
        private X509Certificate2 extractCertFromJWT(String token)
        {
            string[] parts = token.Split('.');
            string header = parts[0];
            string payload = parts[1];
            string headerJson = Encoding.UTF8.GetString(Base64UrlDecode(header));
            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));
            var headerData = JObject.Parse(headerJson);
            var x5cToken = (headerData["x5c"][0]);
            string x5cElement = Base64Decode(x5cToken.ToString());
            X509Certificate2 x509 = new X509Certificate2(Convert.FromBase64String(x5cElement));
            return x509;
        }
        private void validateTrustedCertificate(X509Certificate2Collection trustStore, X509Certificate2 cert)
        {
            var chain = new X509Chain();
            foreach (X509Certificate2 x509 in trustStore)
            {
                chain.ChainPolicy.ExtraStore.Add(x509);
            }

            // You can alter how the chain is built/validated. 
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreWrongUsage;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            chain.ChainPolicy.VerificationTime = DateTime.Now;
            chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 0);
            Console.WriteLine(chain.ChainElements);
            // Do the preliminary validation. 
            //var primaryCert = new X509Certificate2(primaryCertificate); 
            if (!chain.Build(cert))
            {
                throw new Exception("chain build failed");
            }
            // Make sure we have the same number of elements. 
            if (chain.ChainElements.Count != chain.ChainPolicy.ExtraStore.Count + 1)
            {
                throw new Exception("chain count failed");
            }
            //return false; 

            // Make sure all the thumbprints of the CAs match up. 
            // The first one should be 'primaryCert', leading up to the root CA. 
            for (var i = 1; i < chain.ChainElements.Count; i++)
            {
                if (chain.ChainElements[i].Certificate.Thumbprint != chain.ChainPolicy.ExtraStore[i - 1].Thumbprint)
                {
                    throw new Exception("thumbprint failed");
                }
                //return false; 
            }
            //return true; 
        }
        private JwtSecurityToken ValidateTokenAndSetIdentity(string token, X509SecurityKey securityKey)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = GetValidationParameters(securityKey);
            SecurityToken validToken;
            tokenHandler.ValidateToken(token, validationParameters, out validToken);
            JwtSecurityToken validatedJwt = validToken as JwtSecurityToken;
            //Thread.CurrentPrincipal = principal; 
            //HttpContext.Current.User = principal; 
            //Console.WriteLine("out"); 
            return validatedJwt;
        }
        private static TokenValidationParameters GetValidationParameters(X509SecurityKey securityKey)
        {
            return new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = securityKey,
            };
        }
        private string getPayload(string token)
        {
            string[] parts = token.Split('.');
            string payload = parts[1];
            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));
            var payloadData = JObject.Parse(payloadJson);
            var payloadhash = (payloadData["payloadhash"]);
            return payloadhash.ToString();
        }
        public static string GetSha256FromString(string strData)
        {
            var message = System.Text.Encoding.UTF8.GetBytes(strData);
            SHA256Managed hashString = new SHA256Managed();
            SHA256 mySHA256 = SHA256.Create();
            string hex = "";

            //var hashValue = hashString.ComputeHash(message); 
            var hashval = mySHA256.ComputeHash(message);
            foreach (byte x in hashval)
            {
                hex += String.Format("{0:x2}", x);
            }
            return hex;
        }
        private static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding 
            output = output.Replace('_', '/'); // 63rd char of encoding 
            switch (output.Length % 4) // Pad with trailing '='s 
            {
                case 0: break; // No pad chars in this case 
                case 1: output += "==="; break; // Three pad chars 
                case 2: output += "=="; break; // Two pad chars 
                case 3: output += "="; break; // One pad char 
                default: throw new System.Exception("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder 
            return converted;
        }
        private static string Base64Decode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding 
            output = output.Replace('_', '/'); // 63rd char of encoding 
            switch (output.Length % 4) // Pad with trailing '='s 
            {
                case 0: break; // No pad chars in this case 
                case 1: output += "==="; break; // Three pad chars 
                case 2: output += "=="; break; // Two pad chars 
                case 3: output += "="; break; // One pad char 
                default: throw new System.Exception("Illegal base64url string!");
            }
            return output;
        }
        public class StargateJWTException : Exception
        {
            public StargateJWTException(String message)
            {
                throw new Exception(message);
            }
        }
    }
}