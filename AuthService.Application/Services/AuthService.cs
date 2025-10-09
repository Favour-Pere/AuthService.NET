using AuthService.Application.Contracts;
using AuthService.Application.DTOs;
using AuthService.Domain.Entities;
using BCrypt.Net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Application.Services
{
    public class AuthService : IAuthService
    {
        private readonly IUserRepository _userRepository;

        private readonly ITokenService _tokenService;

        private readonly IEmailService _emailService;

        public AuthService(IUserRepository userRepository, IEmailService emailService, ITokenService tokenService)
        {
            _userRepository = userRepository;
            _emailService = emailService;
            _tokenService = tokenService;
        }

        public async Task<AuthResponse> RegisterAsync(RegisterUserRequest request)
        {
            if (await _userRepository.EmailExistsAsync(request.Email))
            {
                throw new InvalidOperationException("Email already in use.");
            }

            var passwordHash = HashPassword(request.
                Password);

            var user = new User(request.Email, passwordHash, request.FullName);

            await _userRepository.AddAsync(user);
            await _userRepository.SaveChangesAsync();

            var accessToken = _tokenService.GenerateAccessToken(user);

            var refreshToken = _tokenService.GenerateRefreshToken(user.Id);

            //TODO: Fix the verification link
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
            var user = await _userRepository.GetByEmailAsync(request.Email) ?? throw new InvalidOperationException("Invalid email or password.");

            if (!VerifyPassword(request.Password, user.PasswordHash))
            {
                throw new InvalidOperationException("Invalid email or password.");
            }

            var jwt = _tokenService.GenerateAccessToken(user);

            var refreshToken = _tokenService.GenerateRefreshToken(user.Id);

            return new AuthResponse
            {
                Email = user.Email,
                Message = "Login Successful",
                AccessToken = jwt,
                RefreshToken = refreshToken.Token,
                ExpiresAt = refreshToken.ExpiresAt
            };
        }

        private static string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        private static bool VerifyPassword(string password, string hash)
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }

        public async Task<bool> VerifyEmailAsync(string email, string token)
        {
            var user = await _userRepository.GetByEmailAsync(email);
            if (user is null)
            {
                return false;
            }

            user.VerifyEmail();
            await _userRepository.UpdateAsync(user);
            return true;
        }

        public async Task<AuthResponse> RefreshTokenAsync(string refreshToken)
        {
            var token = await _userRepository.GetRefreshTokenAsync(refreshToken);

            if (token is null || !token.IsActive())
            {
                throw new UnauthorizedAccessException("Invalid or expired refresh token.");
            }

            var user = await _userRepository.GetByIdAsync(token.UserId);

            if (user is null)
                throw new UnauthorizedAccessException("Invalid user.");

            var newJwt = _tokenService.GenerateAccessToken(user);

            var newRefreshToken = _tokenService.GenerateRefreshToken(user.Id);

            await _userRepository.AddRefreshTokenAsync(newRefreshToken);

            token.Revoke();

            await _userRepository.UpdateRefreshTokenAsync(token);

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
            var token = await _userRepository.GetRefreshTokenAsync(refreshToken);

            if (token is null || token.IsRevoked)
                return false;

            token.Revoke();
            await _userRepository.UpdateRefreshTokenAsync(token);

            return true;
        }
    }
}