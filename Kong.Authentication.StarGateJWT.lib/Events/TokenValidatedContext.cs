using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace Kong.Authentication.StarGateJWT.lib.Events
{
    public class TokenValidatedContext : ResultContext<JwtOptions>
    {
        public TokenValidatedContext(
           HttpContext context,
           AuthenticationScheme scheme,
           JwtOptions options)
           : base(context, scheme, options) { }

        public SecurityToken SecurityToken { get; set; }
    }
}
