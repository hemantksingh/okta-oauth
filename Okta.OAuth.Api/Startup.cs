﻿/*!
 * Copyright (c) 2016, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

using System;
using Microsoft.Owin;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Web.Http;

[assembly: OwinStartup(typeof(Okta.OAuth.Api.Startup))]

namespace Okta.OAuth.Api
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            var config = new HttpConfiguration();
            config.EnableSystemDiagnosticsTracing();

            var clientId = Environment.GetEnvironmentVariable("OAUTH_CLIENTID");
	        var tenantUrl = Environment.GetEnvironmentVariable("OAUTH_AUTHORITY");

	        app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions
            {
                AccessTokenFormat = GetAccessTokenFormat(tenantUrl, clientId)
            });
        }

		/// <summary>
		/// Specifies validation options for the access token.
		/// </summary>
		/// <param name="tenantUrl"></param>
		/// <param name="clientId"></param>
		/// <returns></returns>
	    private static CustomValidatingJwtFormat GetAccessTokenFormat(string tenantUrl, string clientId)
	    {
		    var tokenValidationParameters = new TokenValidationParameters
		    {
			    ValidAudience = tenantUrl,
			    ValidateAudience = true,
			    ValidIssuer = tenantUrl,
			    ValidateIssuer = true,
		    };

		    var additionalTokenValidationParamters = new Dictionary<string, string>
		    {
			    // Validate Client ID claim
			    ["cid"] = clientId
		    };

		    var securityTokenProvider = new OpenIdConnectCachingSecurityTokenProvider(
			    tenantUrl + "/.well-known/openid-configuration");

		    return new CustomValidatingJwtFormat(tokenValidationParameters,
			    additionalTokenValidationParamters,
			    securityTokenProvider);
	    }
    }
}