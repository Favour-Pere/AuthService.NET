using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Application.Common
{
    public class JwtSettings
    {
        public string SecretKey { get; set; } = string.Empty;
        public string? Issuer { get; set; }
        public string? Audience { get; set; }
        public int ExpiryMinutes { get; set; } = 60; // default to 60 minutes

        public int RefreshTokenExpiryDays { get; set; } = 7; // default to 7 days
    }
}