using System;
using System.Configuration;
using IdentityModel.Client;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

[assembly: OwinStartup(typeof(Okta.Samples.OAuth.CodeFlow.Startup))]

namespace Okta.Samples.OAuth.CodeFlow
{
	public class Startup
	{
		public void Configuration(IAppBuilder app)
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

						TokenResponse tokenResponse =
							await client.GetTokenAuthorizationCode(
								authCodeReceived.Code, 
								authCodeReceived.RedirectUri);
						UserInfoResponse userInfoResponse = await client.GetUser(tokenResponse.AccessToken);

						authCodeReceived.AuthenticationTicket = new AuthenticationTicket(
							new Identity(tokenResponse,
									userInfoResponse,
									authCodeReceived.AuthenticationTicket.Identity.AuthenticationType)
								.ToClaimsIdentity(),
							authCodeReceived.AuthenticationTicket.Properties);
					}
				}
			});
		}

		public static OAuthConfig GetOAuthConfig()
		{
			var oAuthConfig = new OAuthConfig(
				Environment.GetEnvironmentVariable("OAUTH_AUTHORITY"),
				Environment.GetEnvironmentVariable("OAUTH_CLIENTID"),
				Environment.GetEnvironmentVariable("OAUTH_CLIENTSECRET"),
				ConfigurationManager.AppSettings["okta:OAuthRedirectUri"],
				ConfigurationManager.AppSettings["okta:OAuthResponseType"],
				ConfigurationManager.AppSettings["okta:OAuthScopes"]
			);
			return oAuthConfig;
		}
	}
}