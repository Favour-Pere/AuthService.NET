using AuthService.Domain.Common;

namespace AuthService.Domain.Entities
{
    public class User : BaseEntity
    {
        public string Email { get; private set; } = string.Empty;

        public string PasswordHash { get; private set; } = string.Empty;

        public string? FullName { get; private set; }

        public string? AvatarUrl { get; private set; }

        public bool IsEmailVerified { get; private set; } = false;

        public string Role { get; private set; } = "User";

        public ICollection<RefreshToken>? RefreshTokens { get; private set; } = [];

        private User()
        { }

        public User(string email, string passwordHash, string? fullname = null)
        {
            Email = email;
            PasswordHash = passwordHash;
            FullName = fullname;
        }

        public void VerifyEmail()
        {
            IsEmailVerified = true;
            UpdatedAt = DateTime.UtcNow;
        }

        public void UpdateProfile(string? fullname, string? avatarUrl)
        {
            if (!string.IsNullOrWhiteSpace(fullname))
            {
                FullName = fullname;
            }
            if (!string.IsNullOrWhiteSpace(avatarUrl))
            {
                AvatarUrl = avatarUrl;
            }
            MarkUpdated();
        }

        public void ChangePassword(string newPasswordHash)
        {
            PasswordHash = newPasswordHash;
            MarkUpdated();
        }

        public void AssignRole(string role)
        {
            Role = role;
            MarkUpdated();
        }
    }
}