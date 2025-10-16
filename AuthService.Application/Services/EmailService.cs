using AuthService.Application.Contracts;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Configuration;
using MimeKit;
using System;
using System.Threading.Tasks;

namespace AuthService.Application.Services
{
    public class EmailService(IConfiguration configuration) : IEmailService
    {
        private readonly IConfiguration _configuration = configuration;

        /// <summary>
        /// Sends an email verification message to the specified address.
        /// </summary>
        public async Task SendEmailVerificationAsync(string to, string verificationLink)
        {
            var subject = "Verify Your Email Address";
            var body = $@"
                <h2>Welcome to AuthService!</h2>
                <p>Click the link below to verify your email:</p>
                <a href='{verificationLink}'>Verify Email</a>
            ";

            await SendEmailAsync(to, subject, body);
        }

        /// <summary>
        /// Sends a password reset email to the specified address.
        /// </summary>
        public async Task SendPasswordResetAsync(string to, string resetLink)
        {
            var subject = "Password Reset Request";
            var body = $@"
                <h3>Password Reset</h3>
                <p>You requested a password reset. Click below to reset it:</p>
                <a href='{resetLink}'>Reset Password</a>
            ";

            await SendEmailAsync(to, subject, body);
        }

        /// <summary>
        /// Sends a welcome email to the specified address.
        /// </summary>
        public async Task SendWelcomeEmailAsync(string to, string name)
        {
            var subject = "Welcome to AuthService!";
            var body = $@"
                <h2>Hi {name},</h2>
                <p>Welcome to our platform! We're excited to have you on board.</p>
            ";

            await SendEmailAsync(to, subject, body);
        }

        private async Task SendEmailAsync(string to, string subject, string htmlBody)
        {
            var emailSettings = _configuration.GetSection("EmailSettings");
            var fromName = emailSettings["FromName"] ?? "Auth Service";
            var fromAddress = emailSettings["FromAddress"];
            var smtpServer = emailSettings["SmtpServer"];
            var portString = emailSettings["Port"];
            var username = emailSettings["Username"];
            var password = emailSettings["Password"];

            if (string.IsNullOrWhiteSpace(fromAddress) ||
                string.IsNullOrWhiteSpace(smtpServer) ||
                string.IsNullOrWhiteSpace(portString) ||
                string.IsNullOrWhiteSpace(username) ||
                string.IsNullOrWhiteSpace(password))
            {
                throw new InvalidOperationException("Email settings are not properly configured.");
            }

            if (!int.TryParse(portString, out int port))
            {
                throw new InvalidOperationException("Email port is not a valid integer.");
            }

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(fromName, fromAddress));
            message.To.Add(MailboxAddress.Parse(to));
            message.Subject = subject;

            var builder = new BodyBuilder { HtmlBody = htmlBody };
            message.Body = builder.ToMessageBody();

            using var smtp = new SmtpClient();
            try
            {
                await smtp.ConnectAsync(smtpServer, port, SecureSocketOptions.StartTls);
                await smtp.AuthenticateAsync(username, password);
                await smtp.SendAsync(message);
            }
            catch (Exception ex)
            {
                // TODO: Add logging here if desired
                throw new InvalidOperationException("Failed to send email.", ex);
            }
            finally
            {
                if (smtp.IsConnected)
                    await smtp.DisconnectAsync(true);
            }
        }
    }
}