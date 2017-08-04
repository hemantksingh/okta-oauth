using System;
using System.Linq;
using System.Security.Claims;
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

		public async Task<TokenResponse> GetToken(
			string authCode,
			string redirectUri, 
			AuthenticationStyle authenticationStyle = AuthenticationStyle.BasicAuthentication)
		{
			_logger.WriteInformation($"Getting token for authCode: '{authCode}' " +
			                         $"redirectUri: '{redirectUri}' " +
									 $" & authenticationStyle: '{authenticationStyle}'");

			var tokenClient = new TokenClient(
				_config.OidcAuthority + "/oauth2/v1/token",
				_config.ClientId,
				_config.ClientSecret,
				authenticationStyle);

			TokenResponse tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(
				authCode,
				redirectUri);

			if (!tokenResponse.IsError) return tokenResponse;

			_logger.WriteError(tokenResponse.Error);
			throw new Exception(tokenResponse.Error);
		}

		public async Task<UserInfoResponse> GetUser(string accessToken)
		{
			var client = new UserInfoClient(
				new Uri(_config.OidcAuthority + "/oauth2/v1/userinfo"),
				accessToken
			);

			return await client.GetAsync();
		}

		public ClaimsIdentity CreateIdentity(TokenResponse tokenResponse,
			UserInfoResponse userInfoResponse,
			string authenticationType)
		{
			_logger.WriteInformation($"Creating identity authenticationType: '{authenticationType}'");

			var identity = new ClaimsIdentity(
				userInfoResponse.GetClaimsIdentity().Claims,
				authenticationType);
			var expiresAt = DateTime.Now.AddSeconds(tokenResponse.ExpiresIn).ToLocalTime().ToString();

			identity.AddClaim(new Claim("id_token", tokenResponse.IdentityToken));
			identity.AddClaim(new Claim("access_token", tokenResponse.AccessToken));
			identity.AddClaim(new Claim("expires_at", expiresAt));

			if (!string.IsNullOrWhiteSpace(tokenResponse.RefreshToken))
				identity.AddClaim(new Claim("refresh_token", tokenResponse.RefreshToken));

			var nameClaim = new Claim(ClaimTypes.Name,
				userInfoResponse.GetClaimsIdentity().Claims.FirstOrDefault(c => c.Type == "name")?.Value);
			identity.AddClaim(nameClaim);
			return identity;
		}

		public async Task<ClaimsIdentity> GetIdentity(string authCode,
			string redirectUri,
			string authenticationType)
		{
			TokenResponse tokenResponse = await GetToken(authCode, redirectUri);
			UserInfoResponse userInfoResponse = await GetUser(tokenResponse.AccessToken);

			return CreateIdentity(tokenResponse,
				userInfoResponse,
				authenticationType);
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
}