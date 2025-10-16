using AuthService.Domain.Entities;

namespace AuthService.Application.Contracts
{
    public interface ITokenService
    {
        Task<RefreshToken> GetRefreshTokenAsync(string refreshToken);

        string GenerateAccessToken(User user);

        RefreshToken GenerateRefreshToken(Guid userId);

        bool ValidateAccessToken(string token);
    }
}