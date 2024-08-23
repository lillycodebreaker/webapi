using System;
using Microsoft.AspNetCore.Authentication;

namespace Kong.Authentication.StarGateJWT.lib
{
    public static class JwtExtensions
    {
        public static AuthenticationBuilder AddJwt(this AuthenticationBuilder builder)
           => builder.AddJwt(JwtDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddJwt(this AuthenticationBuilder builder, Action<JwtOptions> configureOptions)
            => builder.AddJwt(JwtDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddJwt(this AuthenticationBuilder builder, string authenticationScheme, Action<JwtOptions> configureOptions)
            => builder.AddJwt(authenticationScheme, displayName: null, configureOptions: configureOptions);

        public static AuthenticationBuilder AddJwt(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<JwtOptions> configureOptions)
        {
            
            return builder.AddScheme<JwtOptions, JwtHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
