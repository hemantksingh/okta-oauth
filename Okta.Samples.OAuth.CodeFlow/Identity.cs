using System;
using System.Linq;
using System.Security.Claims;
using IdentityModel.Client;

namespace Okta.Samples.OAuth.CodeFlow
{
	public class Identity
	{
		private readonly TokenResponse _tokenResponse;
		private readonly UserInfoResponse _userInfoResponse;
		private readonly string _authenticationType;

		public Identity(TokenResponse tokenResponse, 
			UserInfoResponse userInfoResponse, 
			string authenticationType)
		{
			this._tokenResponse = tokenResponse;
			this._userInfoResponse = userInfoResponse;
			this._authenticationType = authenticationType;
		}

		public ClaimsIdentity ToClaimsIdentity()
		{
			var identity = new ClaimsIdentity(
				_userInfoResponse.GetClaimsIdentity().Claims,
				_authenticationType);
			var expiresAt = DateTime.Now.AddSeconds(_tokenResponse.ExpiresIn).ToLocalTime().ToString();

			identity.AddClaim(new Claim("id_token", _tokenResponse.IdentityToken));
			identity.AddClaim(new Claim("access_token", _tokenResponse.AccessToken));
			identity.AddClaim(new Claim("expires_at", expiresAt));

			if (!string.IsNullOrWhiteSpace(_tokenResponse.RefreshToken))
				identity.AddClaim(new Claim("refresh_token", _tokenResponse.RefreshToken));

			var nameClaim = new Claim(ClaimTypes.Name,
				_userInfoResponse.GetClaimsIdentity().Claims.FirstOrDefault(c => c.Type == "name")?.Value);
			identity.AddClaim(nameClaim);
			return identity;
		}
	}
}