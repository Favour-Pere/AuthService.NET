using AuthService.Application.Contracts;
using AuthService.Domain.Entities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthService.Application.Services
{
    public class TokenService(IConfiguration configuration, IAppRepository<RefreshToken> refreshTokenRepo) : ITokenService
    {
        private readonly IConfiguration _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        private readonly IAppRepository<RefreshToken> _refreshTokenRepo = refreshTokenRepo ?? throw new ArgumentNullException(nameof(refreshTokenRepo));

        public string GenerateAccessToken(User user)
        {
            ArgumentNullException.ThrowIfNull(user);

            var jwtSettings = _configuration.GetSection("JwtSettings");

            var secretKey = jwtSettings["SecretKey"];
            if (string.IsNullOrWhiteSpace(secretKey))
                throw new InvalidOperationException("JWT SecretKey is not configured.");

            var issuer = jwtSettings["Issuer"];
            var audience = jwtSettings["Audience"];

            if (!double.TryParse(jwtSettings["ExpiryMinutes"], out double expiryMinutes))
                expiryMinutes = 60; // sensible default

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
                new Claim("username", user.FullName ?? string.Empty),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: string.IsNullOrWhiteSpace(issuer) ? null : issuer,
                audience: string.IsNullOrWhiteSpace(audience) ? null : audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(expiryMinutes),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public RefreshToken GenerateRefreshToken(Guid userId)
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);

            // Optionally make Base64 URL-safe if you will use token in URLs.
            var token = Convert.ToBase64String(randomNumber);

            var jwtSettings = _configuration.GetSection("JwtSettings");
            if (!int.TryParse(jwtSettings["RefreshTokenExpiryDays"], out var expiryDays))
                expiryDays = 7;

            return new RefreshToken
            (
                token,
                DateTime.UtcNow.AddDays(expiryDays),
                userId
            );
        }

        public async Task<RefreshToken> GetRefreshTokenAsync(string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(refreshToken))
                return null!;

            // Use repository to find token; expected to return an enumerable (FindAsync) or similar.
            // This implementation assumes IAppRepository<RefreshToken>.FindAsync exists and returns IEnumerable<RefreshToken>.
            try
            {
                var list = await _refreshTokenRepo.FindAsync(rt => rt.Token == refreshToken);
                var tokenEntity = list?.FirstOrDefault();
                return tokenEntity!;
            }
            catch (NotImplementedException)
            {
                // If repository does not provide FindAsync, throw a clear error so caller can address wiring.
                throw new NotImplementedException("Repository does not implement FindAsync. Implement or adjust TokenService to query tokens differently.");
            }
        }

        public bool ValidateAccessToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token)) return false;

            var jwtSettings = _configuration.GetSection("JwtSettings");
            var secretKey = jwtSettings["SecretKey"];
            if (string.IsNullOrWhiteSpace(secretKey))
                return false;

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(secretKey);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidateAudience = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            // If issuer/audience are configured, validate them (optional)
            var issuer = jwtSettings["Issuer"];
            var audience = jwtSettings["Audience"];
            if (!string.IsNullOrWhiteSpace(issuer))
            {
                validationParameters.ValidateIssuer = true;
                validationParameters.ValidIssuer = issuer;
            }
            if (!string.IsNullOrWhiteSpace(audience))
            {
                validationParameters.ValidateAudience = true;
                validationParameters.ValidAudience = audience;
            }

            try
            {
                tokenHandler.ValidateToken(token, validationParameters, out _);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}