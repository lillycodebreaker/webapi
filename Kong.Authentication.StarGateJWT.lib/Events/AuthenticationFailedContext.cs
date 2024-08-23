using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Kong.Authentication.StarGateJWT.lib.Events
{
    public class AuthenticationFailedContext : ResultContext<JwtOptions>
    {
        public AuthenticationFailedContext(
           HttpContext context,
           AuthenticationScheme scheme,
           JwtOptions options)
           : base(context, scheme, options) { }

        public Exception Exception { get; set; }
    }
}
