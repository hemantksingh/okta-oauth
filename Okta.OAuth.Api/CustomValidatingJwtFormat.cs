﻿using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Jwt;
using System.Collections.Generic;
using System;
using System.Linq;
using System.IdentityModel.Tokens;

namespace Okta.OAuth.Api
{
    /// <summary>
    /// Extends <see cref="JwtFormat"/> to allow validation of any claim.
    /// </summary>
    internal class CustomValidatingJwtFormat : JwtFormat, ISecureDataFormat<AuthenticationTicket>
    {
	    private readonly IReadOnlyDictionary<string, string> _additionalTokenValidationParamters;

	    public CustomValidatingJwtFormat(
            TokenValidationParameters tvps, 
            IReadOnlyDictionary<string, string> additionalTokenValidationParamters,
            OpenIdConnectCachingSecurityTokenProvider securityTokenProvider)
            : base(tvps, securityTokenProvider)
        {
            if (_additionalTokenValidationParamters == null)
            {
                _additionalTokenValidationParamters = new Dictionary<string, string>();
            }

	        _additionalTokenValidationParamters = additionalTokenValidationParamters;
        }

        public new AuthenticationTicket Unprotect(string protectedText)
        {
            var result = base.Unprotect(protectedText);

            ThrowIfValidationFails(result, _additionalTokenValidationParamters);

            return result;
        }

        private static void ThrowIfValidationFails(
            AuthenticationTicket ticket,
            IReadOnlyDictionary<string, string> customParameters)
        {
            foreach (var claimPair in customParameters)
            {
                var claimInTicket = ticket.Identity.Claims.SingleOrDefault(c => c.Type == claimPair.Key);
                if (claimInTicket?.Value != claimPair.Value)
                {
                    throw new ArgumentOutOfRangeException(claimPair.Key);
                }
            }
        }
    }
}
