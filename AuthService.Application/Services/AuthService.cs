using AuthService.Application.Contracts;
using AuthService.Application.DTOs;
using AuthService.Domain.Entities;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthService.Application.Services
{
    public class AuthService(
        IAppRepository<User> userRepository,
        IAppRepository<RefreshToken> refreshTokenRepository,
        ITokenService tokenService,
        IEmailService emailService) : IAuthService
    {
        private readonly IAppRepository<User> userRepo = userRepository;
        private readonly IAppRepository<RefreshToken> refreshTokenRepo = refreshTokenRepository;
        private readonly ITokenService _tokenService = tokenService;
        private readonly IEmailService _emailService = emailService;

        public async Task<AuthResponse> RegisterAsync(RegisterUserRequest request)
        {
            var exisiting = (await userRepo.FindAsync(req => req.Email == request.Email)).FirstOrDefault();
            if (exisiting != null)
                throw new InvalidOperationException("Email already in use.");

            var passwordHash = HashPassword(request.Password);
            var user = new User(request.Email, passwordHash, request.FullName);

            await userRepo.AddAsync(user);
            await userRepo.SaveChangesAsync();

            var accessToken = _tokenService.GenerateAccessToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken(user.Id);

            await refreshTokenRepo.AddAsync(refreshToken);
            await refreshTokenRepo.SaveChangesAsync();

            var verificationLink = $"https://example.com/verify?user={user.Id}";
            await _emailService.SendEmailVerificationAsync(user.Email, verificationLink);

            return new AuthResponse
            {
                Email = user.Email,
                Message = "Registration successful. Please check your email to verify your account.",
                AccessToken = accessToken,
                RefreshToken = refreshToken.Token,
                ExpiresAt = refreshToken.ExpiresAt
            };
        }

        public async Task<AuthResponse> LoginAsync(LoginRequest request)
        {
            var user = (await userRepo.FindAsync(u => u.Email == request.Email)).FirstOrDefault() ?? throw new InvalidOperationException("Invalid email or password.");

            if (!VerifyPassword(request.Password, user.PasswordHash))
                throw new InvalidOperationException("Invalid email or password.");

            var jwt = _tokenService.GenerateAccessToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken(user.Id);

            await refreshTokenRepo.AddAsync(refreshToken);
            await refreshTokenRepo.SaveChangesAsync();

            return new AuthResponse
            {
                Email = user.Email,
                Message = "Login Successful",
                AccessToken = jwt,
                RefreshToken = refreshToken.Token,
                ExpiresAt = refreshToken.ExpiresAt
            };
        }

        public async Task<bool> VerifyEmailAsync(string email, string token)
        {
            var user = (await userRepo.FindAsync(u => u.Email == email)).FirstOrDefault() ?? throw new InvalidOperationException("Invalid email.");

            if (user is null)
                return false;

            // TODO: Validate token properly (you’ll implement that later)
            user.VerifyEmail();
            await userRepo.UpdateAsync(user);
            await userRepo.SaveChangesAsync();
            return true;
        }

        public async Task<AuthResponse> RefreshTokenAsync(string refreshToken)
        {
            var token = await refreshTokenRepo.FindAsync(rt => rt.Token == refreshToken);
            var refreshTokenEntity = token.FirstOrDefault();

            if (refreshTokenEntity is null || !refreshTokenEntity.IsActive())
                throw new UnauthorizedAccessException("Invalid or expired refresh token.");

            var user = await userRepo.GetByIdAsync(refreshTokenEntity.UserId)
                ?? throw new UnauthorizedAccessException("Invalid user.");

            var newJwt = _tokenService.GenerateAccessToken(user);
            var newRefreshToken = _tokenService.GenerateRefreshToken(user.Id);

            await refreshTokenRepo.AddAsync(newRefreshToken);
            refreshTokenEntity.Revoke();
            await refreshTokenRepo.UpdateAsync(refreshTokenEntity);
            await refreshTokenRepo.SaveChangesAsync();

            return new AuthResponse
            {
                Email = user.Email,
                Message = "Token refreshed successfully",
                AccessToken = newJwt,
                RefreshToken = newRefreshToken.Token,
                ExpiresAt = newRefreshToken.ExpiresAt
            };
        }

        public async Task<bool> RevokeRefreshTokenAsync(string refreshToken)
        {
            var token = (await refreshTokenRepo.FindAsync(rt => rt.Token == refreshToken)).FirstOrDefault();

            if (token is null || token.IsRevoked)
                return false;

            token.Revoke();
            await refreshTokenRepo.UpdateAsync(token);
            await refreshTokenRepo.SaveChangesAsync();

            return true;
        }

        private static string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        private static bool VerifyPassword(string password, string hash)
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }

        public async Task LogoutAsync(string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(refreshToken))
                return;

            var tokens = await refreshTokenRepo.FindAsync(rt => rt.Token == refreshToken);
            var tokenEntity = tokens.FirstOrDefault();

            if (tokenEntity is null)
                return;

            // Prefer revoking so we keep an audit trail; if you prefer deletion, call RemoveAsync instead.
            if (!tokenEntity.IsRevoked)
            {
                tokenEntity.Revoke();
                await refreshTokenRepo.UpdateAsync(tokenEntity);
                await refreshTokenRepo.SaveChangesAsync();
            }
        }
    }
}