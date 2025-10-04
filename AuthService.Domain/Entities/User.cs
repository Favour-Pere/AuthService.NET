using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Domain.Entities
{
    public class User
    {
        public Guid Id { get; private set; } = Guid.NewGuid();

        public string Email { get; private set; } = string.Empty;

        public string PasswordHash { get; private set; } = string.Empty;

        public string? FullName { get; private set; }

        public string? AvatarUrl { get; private set; }

        public bool IsEmailVerified { get; private set; } = false;

        public string Role { get; private set; } = "User";

        public DateTime CreatedAt { get; private set; } = DateTime.UtcNow;

        public DateTime? UpdatedAt { get; private set; }

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
            UpdatedAt = DateTime.UtcNow;
        }

        public void ChangePassword(string newPasswordHash)
        {
            PasswordHash = newPasswordHash;
            UpdatedAt = DateTime.UtcNow;
        }

        public void AssignRole(string role)
        {
            Role = role;
            UpdatedAt = DateTime.UtcNow;
        }
    }
}