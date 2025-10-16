using AuthService.Application.Contracts;
using AuthService.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Application.Services
{
    public class TokenService : ITokenService
    {
        public string GenerateAccessToken(User user)
        {
            throw new NotImplementedException();
        }

        public RefreshToken GenerateRefreshToken(Guid userId)
        {
            throw new NotImplementedException();
        }

        public Task<RefreshToken> GetRefreshTokenAsync(string refreshToken)
        {
            throw new NotImplementedException();
        }

        public bool ValidateAccessToken(string token)
        {
            throw new NotImplementedException();
        }
    }
}