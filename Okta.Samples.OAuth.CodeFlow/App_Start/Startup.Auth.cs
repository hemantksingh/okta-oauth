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
using IdentityModel.Client;
using System;
using System.Security.Claims;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Notifications;

namespace Okta.Samples.OAuth.CodeFlow
{
	public class OAuthConfig
	{
		public OAuthConfig(string oidcAuthority, 
			string clientId, 
			string clientSecret, 
			string oidcRedirectUri,
			string oidcResponseType, 
			string scopes)
		{
			OidcAuthority = oidcAuthority;
			ClientId = clientId;
			ClientSecret = clientSecret;
			OidcRedirectUri = oidcRedirectUri;
			OidcResponseType = oidcResponseType;
			Scopes = scopes;
		}

		public string OidcAuthority { get; }
		public string ClientId { get; }
		public string ClientSecret { get; }
		public string OidcRedirectUri { get; }
		public string OidcResponseType { get; }
		public string Scopes { get; }
	}

	public partial class Startup
	{
		public void ConfigureAuth(IAppBuilder app)
		{
			var oAuthConfig = new OAuthConfig(
				ConfigurationManager.AppSettings["okta:OAuthAuthority"],
				ConfigurationManager.AppSettings["okta:OauthClientId"],
				ConfigurationManager.AppSettings["okta:OAuthClientSecret"], 
				ConfigurationManager.AppSettings["okta:OAuthRedirectUri"], 
				ConfigurationManager.AppSettings["okta:OAuthResponseType"], 
				ConfigurationManager.AppSettings["okta:OAuthScopes"]
			);

			app.UseCookieAuthentication(new CookieAuthenticationOptions
			{
				AuthenticationType = "Cookies"
			});

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
						// use the code to get the access and refresh token
						TokenResponse tokenResponse = await GetTokenResponse(oAuthConfig, 
							authCodeReceived.Code, 
							authCodeReceived.RedirectUri);

						// use the access token to retrieve claims from userinfo
						UserInfoResponse userInfoResponse = await new UserInfoClient(
								new Uri(oAuthConfig.OidcAuthority + Constants.UserInfoEndpoint),
								tokenResponse.AccessToken)
							.GetAsync();

						var identity = CreateIdentity(userInfoResponse, authCodeReceived, tokenResponse);

						authCodeReceived.AuthenticationTicket = new AuthenticationTicket(
							identity,
							authCodeReceived.AuthenticationTicket.Properties);
					}
				}
			});
		}

		private static ClaimsIdentity CreateIdentity(
			UserInfoResponse userInfoResponse, 
			AuthorizationCodeReceivedNotification authCodeReceived,
			TokenResponse tokenResponse)
		{
			var identity = new ClaimsIdentity(
				userInfoResponse.GetClaimsIdentity().Claims,
				authCodeReceived.AuthenticationTicket.Identity.AuthenticationType);

			identity.AddClaim(new Claim("id_token", authCodeReceived.ProtocolMessage.IdToken));
			identity.AddClaim(new Claim("access_token", tokenResponse.AccessToken));
			identity.AddClaim(new Claim("expires_at", DateTime.Now.AddSeconds(tokenResponse.ExpiresIn).ToLocalTime().ToString()));
			if (tokenResponse.RefreshToken != null)
				identity.AddClaim(new Claim("refresh_token", tokenResponse.RefreshToken));

			var nameClaim = new Claim(ClaimTypes.Name,
				userInfoResponse.GetClaimsIdentity().Claims.FirstOrDefault(c => c.Type == "name")?.Value);
			identity.AddClaim(nameClaim);
			return identity;
		}

		private static async Task<TokenResponse> GetTokenResponse(
			OAuthConfig oAuthConfig, 
			string code, 
			string redirectUri)
		{
			var tokenClient = new TokenClient(
				oAuthConfig.OidcAuthority + Constants.TokenEndpoint,
				oAuthConfig.ClientId,
				oAuthConfig.ClientSecret);

			TokenResponse tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(
				code,
				redirectUri);

			if (tokenResponse.IsError)
			{
				throw new Exception(tokenResponse.Error);
			}
			return tokenResponse;
		}
	}
}