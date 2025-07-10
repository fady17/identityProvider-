// File: Orjnz.IdentityProvider.Web/Infrastructure/DataSeeder.cs
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration; // For IConfiguration
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using Orjnz.IdentityProvider.Web.Data;
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Orjnz.IdentityProvider.Web.Infrastructure
{
    public class DataSeeder : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<DataSeeder> _logger;
        private readonly SeedDataConfiguration _seedDataConfig;
        private readonly IHostEnvironment _hostEnvironment; // Kept for environment check
        private readonly IConfiguration _configuration; // For admin user credentials

        public DataSeeder(
            IServiceProvider serviceProvider,
            IOptions<SeedDataConfiguration> seedDataConfigOptions,
            IHostEnvironment hostEnvironment,
            IConfiguration configuration,
            ILogger<DataSeeder> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
            _seedDataConfig = seedDataConfigOptions.Value ?? new SeedDataConfiguration();
            _hostEnvironment = hostEnvironment; // Used for the IsDevelopment check
            _configuration = configuration;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            if (!_hostEnvironment.IsDevelopment())
            {
                _logger.LogInformation("Skipping data seeding in non-Development environment ({EnvironmentName}).", _hostEnvironment.EnvironmentName);
                return;
            }

            using var scope = _serviceProvider.CreateScope();
            var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();

            _logger.LogInformation("Starting data seeding for Development environment...");

            await SeedAdminRoleAndUserAsync(userManager, roleManager, cancellationToken);
            await SeedProvidersAsync(dbContext, cancellationToken);
            await SeedStandardOidcScopesAsync(scopeManager, cancellationToken);
            await SeedCustomScopesAsync(scopeManager, cancellationToken);
            await SeedApplicationsAsync(applicationManager, dbContext, cancellationToken);

            _logger.LogInformation("Data seeding finished.");
        }

        private async Task SeedProvidersAsync(ApplicationDbContext context, CancellationToken cancellationToken)
        {
            if (_seedDataConfig.Providers == null || !_seedDataConfig.Providers.Any())
            {
                _logger.LogInformation("No Providers configured for seeding.");
                return;
            }

            _logger.LogInformation("Seeding Providers (Create if not exists)...");
            bool anyChanges = false;
            foreach (var providerToSeed in _seedDataConfig.Providers)
            {
                var existingProvider = await context.Providers
                    .FirstOrDefaultAsync(p => p.ShortCode == providerToSeed.ShortCode.ToLowerInvariant(), cancellationToken);

                if (existingProvider == null)
                {
                    var newProvider = new Provider
                    {
                        Id = Guid.NewGuid(),
                        Name = providerToSeed.Name,
                        ShortCode = providerToSeed.ShortCode.ToLowerInvariant(), // Normalize
                        WebsiteDomain = providerToSeed.WebsiteDomain,
                        IsActive = providerToSeed.IsActive,
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow
                    };
                    context.Providers.Add(newProvider);
                    _logger.LogInformation("Prepared Provider for seeding: {ProviderName} ({ProviderShortCode})", newProvider.Name, newProvider.ShortCode);
                    anyChanges = true;
                }
                else
                {
                    _logger.LogDebug("Provider {ProviderName} ({ProviderShortCode}) already exists. Skipping creation.",
                        existingProvider.Name, existingProvider.ShortCode);
                    // No update logic here; managed by UI after initial seed.
                }
            }
            if (anyChanges) { await context.SaveChangesAsync(cancellationToken); }
            _logger.LogInformation("Provider seeding pass completed.");
        }


        private async Task SeedStandardOidcScopesAsync(IOpenIddictScopeManager manager, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Seeding Standard OIDC Scopes (Create if not exists)...");
            await SeedScopeIfNotExistsAsync(manager, Scopes.OpenId, "Sign you in", "Allows the application to verify your identity.", null, cancellationToken);
            await SeedScopeIfNotExistsAsync(manager, Scopes.Profile, "Your User Profile", "Access your basic profile information (name, picture, etc.).", null, cancellationToken);
            await SeedScopeIfNotExistsAsync(manager, Scopes.Email, "Your Email Address", "Access your primary email address and verification status.", null, cancellationToken);
            await SeedScopeIfNotExistsAsync(manager, Scopes.Phone, "Your Phone Number", "Access your phone number and verification status.", null, cancellationToken);
            await SeedScopeIfNotExistsAsync(manager, Scopes.Address, "Your Postal Address", "Access your postal address.", null, cancellationToken);
            await SeedScopeIfNotExistsAsync(manager, Scopes.Roles, "Your Assigned Roles", "Access your assigned roles and permissions.", null, cancellationToken);
            await SeedScopeIfNotExistsAsync(manager, Scopes.OfflineAccess, "Offline Access", "Access your data even when you are not online (issues a refresh token).", null, cancellationToken);
            _logger.LogInformation("Standard OIDC Scope seeding pass completed.");
        }

        private async Task SeedCustomScopesAsync(IOpenIddictScopeManager manager, CancellationToken cancellationToken)
        {
            if (_seedDataConfig.Scopes == null || !_seedDataConfig.Scopes.Any())
            {
                _logger.LogInformation("No Custom Scopes configured for seeding in appsettings.");
                return;
            }
            _logger.LogInformation("Seeding Custom Scopes (Create if not exists)...");
            foreach (var scopeToSeed in _seedDataConfig.Scopes)
            {
                await SeedScopeIfNotExistsAsync(manager, scopeToSeed.Name, scopeToSeed.DisplayName, scopeToSeed.Description, scopeToSeed.Resources, cancellationToken);
            }
            _logger.LogInformation("Custom Scope seeding pass completed.");
        }

        private async Task SeedScopeIfNotExistsAsync(IOpenIddictScopeManager manager, string scopeName, string? displayName, string? description, List<string>? resources, CancellationToken cancellationToken)
        {
            if (await manager.FindByNameAsync(scopeName, cancellationToken) == null)
            {
                var descriptor = new OpenIddictScopeDescriptor
                {
                    Name = scopeName,
                    DisplayName = displayName ?? scopeName,
                    Description = description
                };
                if (resources != null && resources.Any())
                {
                    descriptor.Resources.UnionWith(resources);
                }
                await manager.CreateAsync(descriptor, cancellationToken);
                _logger.LogInformation("Created scope: {ScopeName}", scopeName);
            }
            else
            {
                _logger.LogDebug("Scope {ScopeName} already exists. Skipping creation.", scopeName);
            }
        }


        private async Task SeedApplicationsAsync(IOpenIddictApplicationManager applicationManager, ApplicationDbContext dbContext, CancellationToken cancellationToken)
        {
            if (_seedDataConfig.Applications == null || !_seedDataConfig.Applications.Any())
            {
                _logger.LogInformation("No Applications configured for seeding in appsettings.");
                return;
            }

            _logger.LogInformation("Seeding Applications (Create if not exists, no delete/re-create)...");
            foreach (var appToSeed in _seedDataConfig.Applications)
            {
                if (await applicationManager.FindByClientIdAsync(appToSeed.ClientId, cancellationToken) == null)
                {
                    var descriptor = new OpenIddictApplicationDescriptor
                    {
                        ClientId = appToSeed.ClientId,
                        ClientSecret = (appToSeed.ClientType == ClientTypes.Public) ? null : appToSeed.ClientSecret, // Nullify secret for public clients
                        DisplayName = appToSeed.DisplayName,
                        ClientType = appToSeed.ClientType,
                        ApplicationType = appToSeed.ApplicationType
                    };

                    _logger.LogInformation("Preparing to seed new client {ClientId} with ClientType: {ClientType}, ApplicationType: {ApplicationType}, ClientSecret presence: {HasSecret}",
                        descriptor.ClientId, descriptor.ClientType, descriptor.ApplicationType, !string.IsNullOrEmpty(descriptor.ClientSecret));

                    descriptor.RedirectUris.UnionWith(appToSeed.RedirectUris.Select(uri => new Uri(uri)));
                    descriptor.PostLogoutRedirectUris.UnionWith(appToSeed.PostLogoutRedirectUris.Select(uri => new Uri(uri)));
                    descriptor.Permissions.UnionWith(appToSeed.Permissions);
                    descriptor.Requirements.UnionWith(appToSeed.Requirements);

                    if (appToSeed.Settings != null)
                    {
                        foreach (var setting in appToSeed.Settings)
                        {
                            string? settingValue = ConvertJsonElementToString(setting.Value, appToSeed.ClientId, setting.Key, _logger);
#pragma warning disable CS8601
                            descriptor.Settings[setting.Key] = settingValue;
#pragma warning restore CS8601
                        }
                    }
                    if (appToSeed.Properties != null)
                    {
                        foreach (var prop in appToSeed.Properties)
                        {
                            descriptor.Properties[prop.Key] = prop.Value;
                        }
                    }

                    var newApplicationObject = await applicationManager.CreateAsync(descriptor, cancellationToken);
                    _logger.LogInformation("Created application shell for: {ClientId}", appToSeed.ClientId);

                    if (newApplicationObject is AppCustomOpenIddictApplication customApp)
                    {
                        if (!string.IsNullOrEmpty(appToSeed.ProviderShortCode))
                        {
                            var provider = await dbContext.Providers
                                .FirstOrDefaultAsync(p => p.ShortCode == appToSeed.ProviderShortCode.ToLowerInvariant(), cancellationToken);
                            if (provider != null)
                            {
                                customApp.ProviderId = provider.Id;
                                await applicationManager.UpdateAsync(customApp, cancellationToken);
                                _logger.LogInformation("Successfully linked application {ClientId} to Provider '{ProviderShortCode}' (ID: {ProviderId})",
                                    customApp.ClientId, provider.ShortCode, provider.Id);
                            }
                            else
                            {
                                _logger.LogWarning("Provider with ShortCode '{ProviderShortCode}' not found for application {ClientId}. ProviderId not set.",
                                    appToSeed.ProviderShortCode, appToSeed.ClientId);
                            }
                        }
                    }
                    else if (newApplicationObject != null)
                    {
                        _logger.LogWarning("Created application {ClientId} is NOT of type AppCustomOpenIddictApplication. Cannot set ProviderId. Actual type: {ActualType}",
                            appToSeed.ClientId, newApplicationObject.GetType().FullName);
                    }
                }
                else
                {
                    _logger.LogDebug("Application {ClientId} already exists. Skipping seed creation. Manage via Admin UI for updates.", appToSeed.ClientId);
                    // No automatic update logic here for existing applications.
                }
            }
            _logger.LogInformation("Application seeding pass completed.");
        }

private async Task SeedAdminRoleAndUserAsync(UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager, CancellationToken cancellationToken)
        {
            
            
            // Ensure it checks for existence before creating role/user and assigning role.
            // Ensure it explicitly sets Id = Guid.NewGuid().ToString() for new ApplicationUser and ApplicationRole.
            const string adminRoleName = "IDPAdmin";
            var adminEmail = _configuration["SeedAdminUser:Email"] ?? "admin@orjnz.com";
            var adminPassword = _configuration["SeedAdminUser:Password"] ?? "P@$$wOrd123!";
            var adminFirstName = _configuration["SeedAdminUser:FirstName"] ?? "Admin";
            var adminLastName = _configuration["SeedAdminUser:LastName"] ?? "User";

            var adminRole = await roleManager.FindByNameAsync(adminRoleName);
            if (adminRole == null)
            {
                adminRole = new ApplicationRole(adminRoleName, "Identity Provider Administrator") { Id = Guid.NewGuid().ToString() };
                var roleResult = await roleManager.CreateAsync(adminRole);
                if (roleResult.Succeeded) _logger.LogInformation("Created role: {RoleName}", adminRoleName);
                else { _logger.LogError("Failed to create role {RoleName}", adminRoleName); return; }
            }

            var adminUser = await userManager.FindByEmailAsync(adminEmail);
            if (adminUser == null)
            {
                adminUser = new ApplicationUser
                {
                    Id = Guid.NewGuid().ToString(), UserName = adminEmail, Email = adminEmail,
                    FirstName = adminFirstName, LastName = adminLastName, EmailConfirmed = true, LockoutEnabled = false
                };
                var userResult = await userManager.CreateAsync(adminUser, adminPassword);
                if (userResult.Succeeded) _logger.LogInformation("Created admin user: {AdminEmail}", adminEmail);
                else { _logger.LogError("Failed to create admin user {AdminEmail}", adminEmail); return; }
            }

            if (!await userManager.IsInRoleAsync(adminUser, adminRoleName))
            {
                await userManager.AddToRoleAsync(adminUser, adminRoleName);
                _logger.LogInformation("Assigned user {AdminEmail} to role {RoleName}", adminEmail, adminRoleName);
            }
        }
             private static string? ConvertJsonElementToString(JsonElement element, string clientId, string key, ILogger logger)
        {

            switch (element.ValueKind)
            {
                case JsonValueKind.String: return element.GetString();
                case JsonValueKind.Number: return element.GetRawText();
                case JsonValueKind.True: return "true";
                case JsonValueKind.False: return "false";
                case JsonValueKind.Null: case JsonValueKind.Undefined: return null;
                default:
                    logger.LogWarning("Setting '{Key}' for client '{ClientId}' has complex type '{ValueKind}', storing as raw JSON.", key, clientId, element.ValueKind);
                    return element.GetRawText();
            }
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
