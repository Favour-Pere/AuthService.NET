using Microsoft.EntityFrameworkCore;

namespace AuthService.NET.Data
{
    public class AuthDbContext : DbContext
    {
        public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
        {
        }
    }
}