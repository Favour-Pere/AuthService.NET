using AuthService.Application.DTOs;

namespace AuthService.Application.Contracts
{
    public interface IAuthService
    {
        Task<AuthResponse> RegisterAsync(RegisterUserRequest request);

        Task<AuthResponse> LoginAsync(LoginRequest request);

        Task<bool> VerifyEmailAsync(string email, string token);

        Task<AuthResponse> RefreshTokenAsync(string refreshToken);

        Task<bool> RevokeRefreshTokenAsync(string refreshToken);
    }
}