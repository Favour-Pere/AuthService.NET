using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Application.Contracts
{
    public interface IEmailService
    {
        Task SendEmailVerificationAsync(string to, string verificationLink);

        Task SendPasswordResetAsync(string to, string resetLink);

        Task SendWelcomeEmailAsync(string to, string name);
    }
}