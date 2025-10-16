using AuthService.Application.Contracts;
using AuthService.Application.Services;
using AuthService.Infrastructure.Persistence;
using AuthService.Infrastructure.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace AuthService.Infrastructure.DependencyInjection
{
    public static class InfrastructureServiceRegistration
    {
        /// <summary>
        /// Registers infrastructure services, including DbContext, repositories, and application services.
        /// </summary>
        public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
        {
            var connectionString = configuration.GetConnectionString("Default");
            if (string.IsNullOrWhiteSpace(connectionString))
                throw new InvalidOperationException("Database connection string 'Default' is not configured.");

            services.AddDbContext<AppDbContext>(options =>
                options.UseNpgsql(connectionString));

            services.AddScoped(typeof(IAppRepository<>), typeof(AppRepository<>));
            services.AddScoped<ITokenService, TokenService>();
            services.AddScoped<IEmailService, EmailService>();

            return services;
        }
    }
}