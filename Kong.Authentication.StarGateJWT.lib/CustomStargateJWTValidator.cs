using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Security.Claims;

namespace Kong.Authentication.StarGateJWT.lib
{
    public class CustomStargateJWTValidator
    {
        /*
         
	    Used to validate a Stargate JWT. JWT tokens are base64 encoded string, https://jwt.io to learn more
	    param {String} token - the raw JWT token found in HTTP Header "JWT"
	    param {String} requestBody - an string of the request body found in the HTTP body
	    param {X509Certificate2Collection} trustStore - a loaded instance of your truststore;
        */
        public struct tokenoutputObj
        {
           public ClaimsPrincipal principal { get; set; }
           public  SecurityToken validatedToken { get; set; }
        }
        public tokenoutputObj validate(String token, string requestBody, Boolean ignorePayloadValidation)
        {
            // Decode the unauthenticated JWT to retrieve the x509 cert
            X509Certificate2 cert = extractCertFromJWT(token);

            // Validate x509 cert against our truststore
            validateTrustedCertificate(cert);

            //get payload from token
            string payload = getPayload(token);

            // Instantiates security key for token validation
            X509SecurityKey securityKey = new X509SecurityKey(cert);

            try
            {
                // Validate signature and expiry on JWT
                tokenoutputObj obj = ValidateTokenAndSetIdentity(token, securityKey);
                // Compared HTTP Request body hash with Payload hash claim
                if (!ignorePayloadValidation) validatePayloadHash(requestBody, payload);
                return obj;
            }
            catch(Exception e)
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
                { 
                    // Compare hash of payload to payloadhash from JWT
                    throw new StargateJWTException("Payload validation failure - 'payloadhash' JWT claim (" + payload + ") is not equal to the hash of the request body (" + requestBody + ")");
                }
            }

        }
        private X509Certificate2 extractCertFromJWT(String token)
        {
            try
            {
                string[] parts = token.Split('.');
                string header = parts[0];
                string payload = parts[1];
                string headerJson = Encoding.UTF8.GetString(Base64UrlDecode(header));
                var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));
                var headerData = JObject.Parse(headerJson);
                var x5cToken = (headerData["x5c"][0]);
                string x5cElement = Base64Format(x5cToken.ToString());

                X509Certificate2 x509 = new X509Certificate2(Convert.FromBase64String(x5cElement));
                return x509;
            }
            catch (Exception e)
            {
                throw new StargateJWTException(e.Message + "\n" + token);
            }
        }
        private void validateTrustedCertificate(X509Certificate2 cert)
        {
            //Performs a X.509 chain validation using basic validation policy.
            bool certVerificationResult = cert.Verify();

            if (!certVerificationResult)
            {
                // If the certificate is not trusted throw exception
                throw new Exception("X.509 chain validation Failed" + "\nUnable to validate certificate included in JWT\n[" + cert.ToString() + "]");
            }

            //Performs a X.509 chain validation using own defined validation policy
            var chain = new X509Chain();
            // You can alter how the chain is built/validated.
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.VerificationTime = DateTime.Now;
            chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 0);

            if (!chain.Build(cert))
            {
                //print to console or add to logger for getting chainstatus. it's optional
                /*foreach (X509ChainElement chainElement in chain.ChainElements)
                {
                    foreach (X509ChainStatus chainStatus in chainElement.ChainElementStatus)
                    {
                        Console.WriteLine(chainStatus.StatusInformation);
                    }
                }
                */
                // If the certificate is not trusted throw exception
                throw new Exception("chain build failed" + "\nUnable to validate certificate included in JWT\n[" + cert.ToString()+ "]");  
            }
        }
        private tokenoutputObj ValidateTokenAndSetIdentity(string token, X509SecurityKey securityKey)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            tokenHandler.MapInboundClaims = true;
            var validationParameters = GetValidationParameters(securityKey);
            SecurityToken validToken;
            ClaimsPrincipal principal = tokenHandler.ValidateToken(token, validationParameters, out validToken);

            JwtSecurityToken validatedJwt = validToken as JwtSecurityToken;
            tokenoutputObj obj = new tokenoutputObj();
            obj.principal = principal;
            obj.validatedToken = validatedJwt;
            return obj;
        }
        private static TokenValidationParameters GetValidationParameters(X509SecurityKey securityKey)
        {
            return new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = securityKey,
            };
        }
        private string getPayload(string token)
        {
            try
            {
                string[] parts = token.Split('.');
                string payload = parts[1];
                var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));
                var payloadData = JObject.Parse(payloadJson);
                var payloadhash = (payloadData["payloadhash"]);
                return payloadhash.ToString();
            }catch(Exception e)
            {
                throw new StargateJWTException(e.Message);
            } 
        }
        public static string GetSha256FromString(string strData)
        {
            try
            {
                var message = System.Text.Encoding.UTF8.GetBytes(strData);
                SHA256 mySHA256 = SHA256.Create();
                string hex = "";
                var hashval = mySHA256.ComputeHash(message);
                foreach (byte x in hashval)
                {
                    hex += String.Format("{0:x2}", x);
                }
                mySHA256.Clear();
                return hex;
            }
            catch (Exception e)
            {
                throw new StargateJWTException(e.Message);
            }
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
        private static string Base64Format(string input)
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
