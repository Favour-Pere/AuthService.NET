using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Application.Common
{
    public class EmailSettings
    {
        public string FromName { get; set; } = "Auth Service";

        public string FromAddress { get; set; } = string.Empty;

        public string SmtpServer { get; set; } = string.Empty;

        public int Port { get; set; } = 587;

        public string Username { get; set; } = string.Empty;

        public string Password { get; set; } = string.Empty;

        public bool UseSsl { get; set; } = true;
    }
}