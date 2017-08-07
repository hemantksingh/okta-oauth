using System;
using System.Threading.Tasks;
using IdentityModel.Client;
using Microsoft.Owin.Logging;

namespace Okta.Samples.OAuth.CodeFlow
{
	public class OAuthClient
	{
		private readonly ILogger _logger;
		private readonly OAuthConfig _config;

		public OAuthClient(OAuthConfig config)
		{
			_logger = LoggerFactory.Default.Create(GetType().FullName);
			_config = config;
		}

		public async Task<TokenResponse> GetTokenAuthorizationCode(
			string authCode,
			string redirectUri, 
			AuthenticationStyle authenticationStyle = AuthenticationStyle.BasicAuthentication)
		{
			var uri = _config.OidcAuthority + "/oauth2/v1/token";
			
			var tokenClient = new TokenClient(
				uri,
				_config.ClientId,
				_config.ClientSecret,
				authenticationStyle);

			_logger.WriteInformation($"Getting token from uri: '{uri}' " +
			                         $"redirectUri: '{redirectUri}' " +
			                         $" & authenticationStyle: '{authenticationStyle}'");

			TokenResponse tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(
				authCode,
				redirectUri);

			if (!tokenResponse.IsError) return tokenResponse;

			_logger.WriteError(tokenResponse.Error);
			throw new InvalidOperationException(tokenResponse.Error);
		}

		public async Task<UserInfoResponse> GetUser(string accessToken)
		{
			var client = new UserInfoClient(
				new Uri(_config.OidcAuthority + "/oauth2/v1/userinfo"),
				accessToken
			);

			return await client.GetAsync();
		}

		public async Task<TokenResponse> GetTokenClientCredentials(string clientId, string clientSecret)
		{
			var uri = _config.OidcAuthority + "/oauth2/v1/token";
			var tokenClient = new TokenClient(
				uri,
				clientId,
				clientSecret);
			_logger.WriteInformation($"Requesting token from : '{uri}'");

			var tokenResponse = await tokenClient.RequestClientCredentialsAsync();
			if (!tokenResponse.IsError) return tokenResponse;

			_logger.WriteError(tokenResponse.Error);
			throw new InvalidOperationException(tokenResponse.Error);
		}
	}

	public class OAuthConfig
	{
		public OAuthConfig(string oidcAuthority,
			string clientId,
			string clientSecret,
			string oidcRedirectUri,
			string oidcResponseType,
			string scopes)
		{
			Ensure.ArgumentNonNullOrEmpty(oidcAuthority, "oidcAuthority");
			Ensure.ArgumentNonNullOrEmpty(clientId, "clientId");
			Ensure.ArgumentNonNullOrEmpty(clientSecret, "clientSecret");

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

	public class Ensure
	{
		public static void ArgumentNonNullOrEmpty(string value, string name)
		{
			if(string.IsNullOrWhiteSpace(value))
				throw new ArgumentException($"'{name}' cannot be null or empty.");
		}
	}
}

