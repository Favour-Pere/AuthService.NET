using AuthService.Application.Contracts;
using AuthService.Domain.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AuthService.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class TestController(IEmailService emailService, ITokenService tokenService) : ControllerBase
    {
        private readonly IEmailService _emailService = emailService;
        private readonly ITokenService _tokenService = tokenService;

        [HttpGet("send")]
        public async Task<IActionResult> SendTestEmail()
        {
            await _emailService.SendEmailVerificationAsync("wilsonfavour777@gmail.com", "https://example.com/verify");

            return Ok("Test email sent.");
        }

        [HttpGet("token")]
        public IActionResult GetToken()
        {
            var user = new User(email: "test@example.com", passwordHash: "dummyhash", fullname: "Test User");

            user.AssignRole(Domain.Enums.Role.Admin);

            var token = _tokenService.GenerateAccessToken(user);

            return Ok(new
            {
                accessToken = token,
                email = user.Email,
                role = user.Role.ToString()
            });
        }

        [Authorize]
        [HttpGet("secure")]
        public IActionResult GetSecureData()
        {
            var userEmail = User.FindFirst(ClaimTypes.Email)?.Value ?? User.FindFirst("email")?.Value;
            return Ok(new
            {
                message = "This is a protected endpoint!", 
                userEmail
            });
        }
    }
}