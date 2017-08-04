using Okta.Samples.OAuth.CodeFlow;
using System;
using System.Threading.Tasks;
using IdentityModel.Client;
using NUnit.Framework;

namespace Okta.Tests
{
    public class OAuthClientTests
    {
	    [Test]
	    public void CreatesAuthTokenForClientFlow()
	    {
		    var oAuthConfig = new OAuthConfig(Environment.GetEnvironmentVariable("OAUTH_AUTHORITY"),
			    Environment.GetEnvironmentVariable("OAUTH_CLIENTID"),
			    Environment.GetEnvironmentVariable("OAUTH_CLIENTSECRET"),
			    "",
			    "",
			    "openid email");

		    var client = new OAuthClient(oAuthConfig);

		    Task<TokenResponse> token = client.GetToken(oAuthConfig.ClientId, oAuthConfig.ClientSecret);
		
			Assert.IsNotNull(token.Result);
	    }
    }
}
