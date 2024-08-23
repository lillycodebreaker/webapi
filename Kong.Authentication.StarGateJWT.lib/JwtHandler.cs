using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication;
using Kong.Authentication.StarGateJWT.lib.Events;
using Microsoft.AspNetCore.Http.Internal;
using System.IO;
using static Kong.Authentication.StarGateJWT.lib.CustomStargateJWTValidator;
using Microsoft.Extensions.Configuration;
using System.Security.Principal;
using Newtonsoft.Json.Linq;
using System.Linq;

namespace Kong.Authentication.StarGateJWT.lib
{
    public class JwtHandler : AuthenticationHandler<JwtOptions>
    {
        private bool _isLocalDebug;
        //private IConfiguration _configuration;

        public JwtHandler(IOptionsMonitor<JwtOptions> options, ILoggerFactory logger, UrlEncoder encoder, IDataProtectionProvider dataProtection, ISystemClock clock, IConfiguration configuration)
            : base(options, logger, encoder, clock)
        {
            //_configuration = configuration;
            _isLocalDebug = configuration.GetValue("LocalDebug", false);
        }

        /// <summary>
        /// The handler calls methods on the events which give the application control at certain points where processing is occurring. 
        /// If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        protected new JwtEvents Events
        {
            get => (JwtEvents)base.Events;
            set => base.Events = value;
        }

        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new JwtEvents());

        /// <summary>
        /// Searches the header for a 'JWT' token. If the 'Bearer' token is found, it is validated using <see cref="TokenValidationParameters"/> set in the options.
        /// </summary>
        /// <returns></returns>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if(_isLocalDebug)
            {
                var req = Request;
                if(req.Host.Host != "localhost")
                {
                    return AuthenticateResult.Fail("LocalHostMode?");
                }

                var ticket = new AuthenticationTicket(new System.Security.Claims.ClaimsPrincipal(new GenericPrincipal(new GenericIdentity("odarta1"), new string[] { })), Scheme.Name);
                return AuthenticateResult.Success(ticket);
            }

            string token = null;
            try
            {

                //token ="eyJ4NWMiOlsiTUlJR3REQ0NCSnlnQXdJQkFnSVRhZ0FBTGVuckR5R21WVlFKQUFBQUFBQXQ2VEFOQmdrcWhraUc5dzBCQVFzRkFEQnBNUXN3Q1FZRFZRUUdFd0pWVXpFU01CQUdBMVVFQ0JNSlRXbHVibVZ6YjNSaE1SUXdFZ1lEVlFRSEV3dE5hVzV1WldGd2IyeHBjekVPTUF3R0ExVUVDaE1GVDNCMGRXMHhJREFlQmdOVkJBTVRGMDl3ZEhWdFNXNTBaWEp1WVd4SmMzTjFhVzVuUTBFeU1CNFhEVEU0TURZd01URTRNakUwTlZvWERURTVNRFl3TVRFNE1qRTBOVm93Z1p3eEN6QUpCZ05WQkFZVEFsVlRNUkl3RUFZRFZRUUlFd2xOYVc1dVpYTnZkR0V4RVRBUEJnTlZCQWNUQ0ZCc2VXMXZkWFJvTVNBd0hnWURWUVFLRXhkVmJtbDBaV1JJWldGc2RHZ2dSM0p2ZFhBZ1NXNWpMakVkTUJzR0ExVUVDeE1VUkdGMFlTQkZlSFJsY201aGJHbDZZWFJwYjI0eEpUQWpCZ05WQkFNVEhHZGhkR1YzWVhrdGMzUmhaMlV0WTI5eVpTNXZjSFIxYlM1amIyMHdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFEVHRhbTZBcDRUSklLOEVaZXlOa0RBV2RfZGJIYVFjcllhdWpFbVVjVl9iZU5sUS0zd1NWejBnQU0yTmZETklMR1JRdWtjbi1QbVE3RVJkWnpLbVNFS0daNjFFUkJ0cFNDaWRDT010dExSNlV0cENDT2ZlS2RFMDhyZWNRZ1ZVR1lWdDlLdjFtWDJPMW5jOHFNZHBrSG9pZnFaWEJFUzY3dmxSM2gtYWNfaENMSi1BVjFvTVVQRXl4NU95MWNIdnhxLTJvRzM4eF9GUk1RdHNqSWFPVWQwaVZHVUxTcENiUXRwd1ZocGR5azN6SE82cnBSVFRrM3pjSEg3SHdVaGtORk45Q0tjaHRnVDdET01BeUtOc1pDUms3UGt3eFFmVHJpWVd1Rm9jOEdJdWo0OXdxYUhCdXJSR0lVNlRhRUhNM3B1dDJHaDg2TWRKamYwUWRKQ2owOURBZ01CQUFHamdnSWZNSUlDR3pDQmdRWURWUjBSQkhvd2VJSWdaMkYwWlhkaGVTMXpkR0ZuWlMxamIzSmxMV1ZzY2k1dmNIUjFiUzVqYjIyQ0lHZGhkR1YzWVhrdGMzUmhaMlV0WTI5eVpTMWpkR011YjNCMGRXMHVZMjl0Z2h4bllYUmxkMkY1TFhOMFlXZGxMV052Y21VdWIzQjBkVzB1WTI5dGdoUmtZWFJoTFhOMFlXZGxMbTl3ZEhWdExtTnZiVEFkQmdOVkhRNEVGZ1FVN1BCWGNyY2dnQnM0dW1kNWkyLWY1a0ZGaXE4d0h3WURWUjBqQkJnd0ZvQVVkMjZ1dUxpd0M5VjZHQXpKX0VKZmNIQ1hrU2d3UmdZRFZSMGZCRDh3UFRBN29EbWdONFkxYUhSMGNEb3ZMMjlqYzNBdWIzQjBkVzB1WTI5dEwzQnJhUzlQY0hSMWJVbHVkR1Z5Ym1Gc1NYTnpkV2x1WjBOQk1pNWpjbXd3ZVFZSUt3WUJCUVVIQVFFRWJUQnJNRUVHQ0NzR0FRVUZCekFDaGpWb2RIUndPaTh2YjJOemNDNXZjSFIxYlM1amIyMHZjR3RwTDA5d2RIVnRTVzUwWlhKdVlXeEpjM04xYVc1blEwRXlMbU55ZERBbUJnZ3JCZ0VGQlFjd0FZWWFhSFIwY0RvdkwyOWpjM0F1YjNCMGRXMHVZMjl0TDI5amMzQXdDd1lEVlIwUEJBUURBZ1N3TUQwR0NTc0dBUVFCZ2pjVkJ3UXdNQzRHSmlzR0FRUUJnamNWQ0lXRjdncUI2dklHaHZtVEZicWZEb0xFOFg2QldvYmJzbjJIcDhBT0FnRmtBZ0VVTUIwR0ExVWRKUVFXTUJRR0NDc0dBUVVGQndNQkJnZ3JCZ0VGQlFjREFqQW5CZ2tyQmdFRUFZSTNGUW9FR2pBWU1Bb0dDQ3NHQVFVRkJ3TUJNQW9HQ0NzR0FRVUZCd01DTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElDQVFCVXBoTzBsS0oyX1NGeWlZcUM2Z2RzRS10RDlfcmVhU1pfODdtdm9uSFJWSUJBX3Jkb2phNGFicy1xVTFwOXppalViR1d1bHFqSTBWa2RnYzNCdkRkNmk2aWI1bC1nUFJPa0RmUU1VTGFJcmNoRUlvQUZROTlFaVh4bjdPOWZwOVpibGFrTk82ellxTy1DNzJJZWhzQWJaeFFYa2xFRmNuRXUyZGJTSmdZWTM4OVI0R3RnODJReGd2YU9icmJMNHpqWFloU2ZlMXZrU1ZfNzVsQ29SN2F3cXdzUU51RnBGOVQ5cTgtZGN4M1VNZEQ0TEpFLWNLYm1NTFJzcTNwYjI0aGR1ZVBwVVhrd3FGYkhlcEpUOWs1UTdyaXJvLUVZTkt6eFBrYTFEQU8yYk9PWlhFRUt6cU1Qc3BwQXJfUFZObXdMRTU2c3BwUUtNOGE4T0FWZGs3RC1VQW1qQjRCVDFPeVBMUEZOOUhjRlRTd3NvX040RlFLOU53dlh4aGVxVEZoVUI3YVFuRnBNcGhpQUxzZWFpZkxGTDdTTmxYc1JCTXRrX25OQW5iNFdGZzFMMUtiV3pQZVFOYjlfSmdsZlE4emNqNXFRdEVxenpiVTFuT0l0c3lJckdvcndNdENNVUl2MkZBdmdIZ2xINlRVdTg1c2RqbXZPdDhCWGM3T2plTUtjTXpSTzhtOUlJX3hKWEROZmxmeE84MVJSMFNBWTFWODkwRFJVTlMtaXhxMzAwN2Z2VkJhc3pvbGR4WnBjT1F6RlRiU3VsZGlFRlluMWRFNXc4ZExDaG1hdUdETEM0dHBjY2xCUDlaVWc5TGVDUlJzd1Jrc0NDb29BNFQzM0prNXo3N0x2UWlaTGxmUFc3NDBDdmo5MC14Tk1ST1dkQ1RxMDZKSFhQSk1nblEiXSwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJwYXlsb2FkaGFzaCI6IiIsImV4cCI6MTUyODcwNzU1Nn0.dXWC1wfglz1wXWYVy656bFB4FBXx-bM8DYh6f3ZKRdb6DqkhalpDqVsYQp9hw17dVhnWp_vnNTHjNB1nUFm9CTk4e69cXwjjT51VffjsPtWmRQQAXvSLbllN3hYuDKqxPuCDSQaaziVD865H5Dg5ceyHXaul7EIvFO7aI4pHhMGcMnx3gmfKIM6-cMvIXK-d8LIeoGhUX3-GdJ5zl9SHJKoyHlOaeLZcjnWKcm2PlxSkZmqW_vdGUvOm_jb90ZPHE60SNi8MgvCQlPtJylfl-GNSfxlWt9qrm-puI2U9StCezdZ0OvJP2g7H4wqnEkexKWAf9nfxdNTj-I2q3Bitjg";
                string bodyStr = "";
                var req = Request;

                var userInfo = req.Headers["X-UserInfo"].ToString();
                var userName = GetUserMSID(userInfo);
                var principal = default(System.Security.Claims.ClaimsPrincipal);
                if(userName != null)
                {
                    //Console.WriteLine("UserName from X-UserInfo: " + userName);
                    var groups = GetUserGroups(userInfo);
                    principal = new System.Security.Claims.ClaimsPrincipal(new GenericPrincipal(new GenericIdentity(userName), groups.ToArray()));
                }

                // Allows using several time the stream in ASP.Net Core
                req.EnableRewind();

                // Arguments: Stream, Encoding, detect encoding, buffer size 
                // AND, the most important: keep stream opened
                using (StreamReader reader
                          = new StreamReader(req.Body, Encoding.UTF8, true, 1024, true))
                {
                    bodyStr = reader.ReadToEnd();
                }

                // Rewind, so the core is not lost when it looks the body for the request
                req.Body.Position = 0;
                //end of get body

                if (string.IsNullOrEmpty(token))
                {
                    string authorization = Request.Headers["JWT"];

                    token = authorization;
                    // If no authorization header found, nothing to process further
                    if (string.IsNullOrEmpty(authorization))
                    {
                        return AuthenticateResult.Fail("Token?");
                    }
                }

                List<Exception> validationFailures = null;
                tokenoutputObj obj;
                foreach (var validator in Options.SecurityTokenValidators)
                {
                    if (validator.CanReadToken(token))
                    {
                        try
                        {
                            bool ignorePayloadValidation = false;
                            if (String.IsNullOrEmpty(bodyStr))
                            {
                                ignorePayloadValidation = true;
                            }
                            CustomStargateJWTValidator jwtvalidator = new CustomStargateJWTValidator();
                            obj = jwtvalidator.validate(token, bodyStr, ignorePayloadValidation);
                        }
                        catch (Exception ex)
                        {
                            if (validationFailures == null)
                            {
                                validationFailures = new List<Exception>(1);
                            }
                            validationFailures.Add(ex);
                            continue;
                        }

                        var tokenValidatedContext = new TokenValidatedContext(Context, Scheme, Options)
                        {
                            Principal = principal ?? obj.principal,
                            SecurityToken = obj.validatedToken
                        };

                        await Events.TokenValidated(tokenValidatedContext);
                        if (tokenValidatedContext.Result != null)
                        {
                            return tokenValidatedContext.Result;
                        }

                        if (Options.SaveToken)
                        {
                            tokenValidatedContext.Properties.StoreTokens(new[]
                            {
                                new AuthenticationToken { Name = "access_token", Value = token }
                            });
                        }

                        tokenValidatedContext.Success();
                        return tokenValidatedContext.Result;
                    }
                }

                if (validationFailures != null)
                {
                    var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
                    {
                        Exception = (validationFailures.Count == 1) ? validationFailures[0] : new AggregateException(validationFailures)
                    };

                    await Events.AuthenticationFailed(authenticationFailedContext);
                    if (authenticationFailedContext.Result != null)
                    {
                        return authenticationFailedContext.Result;
                    }

                    return AuthenticateResult.Fail(authenticationFailedContext.Exception);
                }

                return AuthenticateResult.Fail("No SecurityTokenValidator available for token: " + token ?? "[null]");
            }
            catch (Exception ex)
            {
                var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
                {
                    Exception = ex
                };
                await Events.AuthenticationFailed(authenticationFailedContext);
                if (authenticationFailedContext.Result != null)
                {
                    return authenticationFailedContext.Result;
                }
                throw;
            }
        }

        private List<string> GetUserGroups(string userInfo)
        {
            if (!string.IsNullOrEmpty(userInfo))
            {
                try
                {
                    var jsonObj = JObject.Parse(userInfo);
                    var grouppArray = (JArray)jsonObj["roles"];
                    var groups = grouppArray.Select(gg => gg.ToString()).ToList();
                    return groups;
                }
                catch(Exception ex)
                {
                    //TODO: Temp code while testing
                    Console.WriteLine(ex.ToString());
                }
            }
            return new List<string>();
        }

        private string GetUserMSID(string userInfo)
        {
            if (!string.IsNullOrEmpty(userInfo))
            {
                try
                {
                    var jsonObj = JObject.Parse(userInfo);
                    var user = jsonObj["id"];
                    return user.ToString();
                }
                catch (Exception ex)
                {
                    //TODO: Temp code while testing
                    Console.WriteLine(ex.ToString());
                }
            }
            return null;
        }
    }
}

