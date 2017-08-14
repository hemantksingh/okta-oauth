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
		    var oAuthConfig = new OAuthConfig(
				Environment.GetEnvironmentVariable("OAUTH_AUTHORITY"),
			    Environment.GetEnvironmentVariable("OAUTH_CLIENTID"),
			    Environment.GetEnvironmentVariable("OAUTH_CLIENTSECRET"),
			    "https://some-callback-url",
			    "token",
			    "openid email");

		    var client = new OAuthClient(oAuthConfig);

		    var exception = Assert.CatchAsync<InvalidOperationException>(() =>
			    client.GetTokenClientCredentials(
				    oAuthConfig.ClientId,
				    oAuthConfig.ClientSecret));

		    Assert.That(exception.Message, Is.EqualTo("unauthorized_client"));
		}
	}
}
