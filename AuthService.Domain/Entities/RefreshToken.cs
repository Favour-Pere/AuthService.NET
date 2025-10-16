using AuthService.Domain.Common;

namespace AuthService.Domain.Entities
{
    public class RefreshToken : BaseEntity
    {
        public string Token { get; private set; } = String.Empty;

        public DateTime ExpiresAt { get; private set; }

        public DateTime? RevokedAt { get; private set; }

        public bool IsRevoked => RevokedAt.HasValue;

        public Guid UserId { get; private set; }

        public User? User { get; private set; }

        private RefreshToken()
        { }

        public RefreshToken(string token, DateTime expiresAt, Guid userId)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                throw new ArgumentException("Token cannot be empty.", nameof(token));
            }
            Token = token;
            ExpiresAt = expiresAt;
            UserId = userId;
        }
       

        public void Revoke()
        {
            if (IsRevoked)
                return;

            RevokedAt = DateTime.UtcNow;
            MarkUpdated();
        }

        public bool IsActive()
        {
            return !IsRevoked && DateTime.UtcNow <= ExpiresAt;
        }
    }
}