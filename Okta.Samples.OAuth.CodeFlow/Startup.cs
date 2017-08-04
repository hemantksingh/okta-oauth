using System.Configuration;
using System.Security.Claims;
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
