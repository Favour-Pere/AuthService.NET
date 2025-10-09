using AuthService.Domain.Entities;

namespace AuthService.Application.Contracts
{
    public interface IUserRepository
    {
        Task<User?> GetByEmailAsync(string email);

        Task<User?> GetByIdAsync(Guid id);

        Task AddAsync(User user);

        Task UpdateAsync(User user);

        Task<bool> EmailExistsAsync(string email);

        Task SaveChangesAsync();

        Task<RefreshToken?> GetRefreshTokenAsync(string token);

        Task AddRefreshTokenAsync(RefreshToken refreshToken);

        Task UpdateRefreshTokenAsync(RefreshToken refreshToken);
    }
}