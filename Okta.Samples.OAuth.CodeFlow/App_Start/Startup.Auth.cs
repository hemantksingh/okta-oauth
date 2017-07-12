/*!
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

using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System.Configuration;
using System.Security.Claims;

namespace Okta.Samples.OAuth.CodeFlow
{
	public partial class Startup
	{
		public void ConfigureAuth(IAppBuilder app)
		{
			app.UseCookieAuthentication(new CookieAuthenticationOptions
			{
				AuthenticationType = "Cookies"
			});

			var oAuthConfig = GetOAuthConfig();
			app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
			{
				ClientId = oAuthConfig.ClientId,
				Authority = oAuthConfig.OidcAuthority,
				RedirectUri = oAuthConfig.OidcRedirectUri,
				ResponseType = oAuthConfig.OidcResponseType,
				Scope = oAuthConfig.Scopes,

				SignInAsAuthenticationType = "Cookies",
				UseTokenLifetime = true,

				Notifications = new OpenIdConnectAuthenticationNotifications
				{
					AuthorizationCodeReceived = async authCodeReceived =>
					{
						var client = new OAuthClient(oAuthConfig);

						ClaimsIdentity identity = await client.GetIdentity(
							authCodeReceived.Code,
							authCodeReceived.RedirectUri,
							authCodeReceived.AuthenticationTicket.Identity.AuthenticationType);

						authCodeReceived.AuthenticationTicket = new AuthenticationTicket(
							identity,
							authCodeReceived.AuthenticationTicket.Properties);
					}
				}
			});
		}

		public static OAuthConfig GetOAuthConfig()
		{
			var oAuthConfig = new OAuthConfig(
				ConfigurationManager.AppSettings["okta:OAuthAuthority"],
				ConfigurationManager.AppSettings["okta:OauthClientId"],
				ConfigurationManager.AppSettings["okta:OAuthClientSecret"],
				ConfigurationManager.AppSettings["okta:OAuthRedirectUri"],
				ConfigurationManager.AppSettings["okta:OAuthResponseType"],
				ConfigurationManager.AppSettings["okta:OAuthScopes"]
			);
			return oAuthConfig;
		}
	}
}