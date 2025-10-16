using AuthService.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthService.Infrastructure.Persistence.Configurations
{
    public class UserConfiguration : IEntityTypeConfiguration<User>
    {
        public void Configure(EntityTypeBuilder<User> builder)
        {
            builder.HasKey(u => u.Id);

            builder.Property(u => u.Email).IsRequired().HasMaxLength(128);

            builder.HasIndex(u => u.Email).IsUnique();

            builder.Property(u => u.PasswordHash).IsRequired();

            builder.Property(u => u.Role).HasConversion<string>().IsRequired();

            builder.HasMany(u => u.RefreshTokens).WithOne(r => r.User).HasForeignKey(r => r.UserId).OnDelete(DeleteBehavior.Cascade);
        }
    }
}