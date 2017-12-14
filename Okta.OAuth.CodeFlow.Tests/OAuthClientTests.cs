using Okta.OAuth.CodeFlow;
using System;
using NUnit.Framework;

namespace Okta.OAuth.CodeFlow.Tests
{
    public class OAuthClientTests
    {
	    [Test]
	    public void CannotGetAcessTokenWithClientCredentialsFlowForUnauthorizedClient()
	    {
		    
			var oAuthConfig = new OAuthConfigBuilder()
			    .OAuthAuthority(Environment.GetEnvironmentVariable("OAUTH_AUTHORITY"))
			    .ClientId(Environment.GetEnvironmentVariable("OAUTH_CLIENTID"))
			    .ClientSecret(Environment.GetEnvironmentVariable("OAUTH_CLIENTSECRET"))
			    .RedirectUri("https://some-callback-url")
			    .ResponseType("token")
			    .Scopes("openid email")
			    .Build();

			var client = new OAuthClient(oAuthConfig);

		    var exception = Assert.CatchAsync<InvalidOperationException>(() =>
			    client.GetTokenClientCredentials(
				    oAuthConfig.ClientId,
				    oAuthConfig.ClientSecret));

		    Assert.That(exception.Message, Is.EqualTo("unauthorized_client"));
		}
	}
}
