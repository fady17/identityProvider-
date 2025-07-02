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
            // ... (SeedAdminRoleAndUserAsync logic remains the same as your previous version) ...
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
            // ... (ConvertJsonElementToString logic remains the same) ...
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
// using Microsoft.EntityFrameworkCore; // Required for EF Core operations like FirstOrDefaultAsync
// using Microsoft.Extensions.DependencyInjection;
// using Microsoft.Extensions.Hosting;
// using Microsoft.Extensions.Logging;
// using Microsoft.Extensions.Options;
// using OpenIddict.Abstractions;
// using System;
// using System.Collections.Generic; // For HashSet and List
// using System.Linq;
// using System.Text.Json;
// using System.Threading;
// using System.Threading.Tasks;
// using Orjnz.IdentityProvider.Web.Data;
// using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities; // For AppCustomOpenIddictApplication
// using static OpenIddict.Abstractions.OpenIddictConstants;
// using Microsoft.AspNetCore.Identity;

// namespace Orjnz.IdentityProvider.Web.Infrastructure
// {
//     public class DataSeeder : IHostedService
//     {
//         private readonly IServiceProvider _serviceProvider;
//         private readonly ILogger<DataSeeder> _logger;
//         private readonly SeedDataConfiguration _seedDataConfig;
//         private readonly IHostEnvironment _hostEnvironment;
//         private readonly IConfiguration _configuration;

//         public DataSeeder(
//             IServiceProvider serviceProvider,
//             IOptions<SeedDataConfiguration> seedDataConfigOptions, // Inject configuration
//             IHostEnvironment hostEnvironment,
//             IConfiguration configuration,
//             ILogger<DataSeeder> logger)
//         {
//             _serviceProvider = serviceProvider;
//             _logger = logger;
//             _seedDataConfig = seedDataConfigOptions.Value ?? new SeedDataConfiguration(); // Handle null config
//             _hostEnvironment = hostEnvironment;
//             _configuration = configuration;
//         }

//         public async Task StartAsync(CancellationToken cancellationToken)
//         {
//             var hostEnvironment = _serviceProvider.GetRequiredService<IHostEnvironment>();
//             if (!hostEnvironment.IsDevelopment()) // Only seed in Development
//             {
//                 _logger.LogInformation("Skipping data seeding in non-Development environment ({EnvironmentName}).", hostEnvironment.EnvironmentName);
//                 return;
//             }

//             using var scope = _serviceProvider.CreateScope();
//             var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
//             var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
//             var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>(); // For Provider operations

//             var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>(); // Get UserManager
//             var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();

//             _logger.LogInformation("Starting data seeding...");

//               // === Seed Admin Role and User ===
//             await SeedAdminRoleAndUserAsync(userManager, roleManager, cancellationToken);
//             // === End Seed Admin Role and User ===

//             // --- 1. Seed Providers ---
//             if (_seedDataConfig.Providers != null && _seedDataConfig.Providers.Any())
//             {
//                 _logger.LogInformation("Seeding Providers...");
//                 foreach (var providerToSeed in _seedDataConfig.Providers)
//                 {
//                     // Check if provider already exists by ShortCode (which should be unique)
//                     var existingProvider = await dbContext.Providers
//                         .FirstOrDefaultAsync(p => p.ShortCode == providerToSeed.ShortCode, cancellationToken);

//                     if (existingProvider == null)
//                     {
//                         var newProvider = new Provider
//                         {
//                             Id = Guid.NewGuid(), // Let database or Guid.NewGuid() assign ID
//                             Name = providerToSeed.Name,
//                             ShortCode = providerToSeed.ShortCode,
//                             WebsiteDomain = providerToSeed.WebsiteDomain,
//                             IsActive = providerToSeed.IsActive, // Use value from seed config
//                             CreatedAt = DateTime.UtcNow,
//                             UpdatedAt = DateTime.UtcNow
//                         };
//                         dbContext.Providers.Add(newProvider);
//                         _logger.LogInformation("Preparing to seed Provider: {ProviderName} ({ProviderShortCode})", newProvider.Name, newProvider.ShortCode);
//                     }
//                     else
//                     {
//                         // Optional: Update existing provider details if they differ.
//                         // For simplicity in development, often "create if not exists" is sufficient for providers.
//                         // If you need to update:
//                         // existingProvider.Name = providerToSeed.Name;
//                         // existingProvider.WebsiteDomain = providerToSeed.WebsiteDomain;
//                         // existingProvider.IsActive = providerToSeed.IsActive;
//                         // existingProvider.UpdatedAt = DateTime.UtcNow;
//                         _logger.LogDebug("Provider {ProviderName} ({ProviderShortCode}) already exists. Skipping creation. Consider update logic if needed.", providerToSeed.Name, providerToSeed.ShortCode);
//                     }
//                 }
//                 // Save all new/updated providers
//                 await dbContext.SaveChangesAsync(cancellationToken);
//                 _logger.LogInformation("Provider seeding finished.");
//             }
//             else
//             {
//                 _logger.LogInformation("No Providers configured for seeding.");
//             }
//             // --- End Provider Seeding ---

            


//             // --- Seed Standard OIDC Scopes FIRST ---
//             await SeedStandardScopeAsync(scopeManager, Scopes.OpenId, "Sign you in", "Allows the application to verify your identity.", cancellationToken);
//             await SeedStandardScopeAsync(scopeManager, Scopes.Profile, "Your User Profile", "Allows the application to access your basic profile information (name, picture, etc.).", cancellationToken);
//             await SeedStandardScopeAsync(scopeManager, Scopes.Email, "Your Email Address", "Allows the application to access your primary email address and verification status.", cancellationToken);
//             await SeedStandardScopeAsync(scopeManager, Scopes.Phone, "Your Phone Number", "Allows the application to access your phone number and verification status.", cancellationToken);
//             await SeedStandardScopeAsync(scopeManager, Scopes.Address, "Your Postal Address", "Allows the application to access your postal address.", cancellationToken);
//             await SeedStandardScopeAsync(scopeManager, Scopes.Roles, "Your Assigned Roles", "Allows the application to access your assigned roles and permissions.", cancellationToken);
//             await SeedStandardScopeAsync(scopeManager, Scopes.OfflineAccess, "Offline Access", "Allows the application to access your data even when you are not online (issues a refresh token).", cancellationToken);
//             // --- END Seed Standard OIDC Scopes ---


//             // Seed Custom Scopes
//             if (_seedDataConfig.Scopes != null)
//             {
//                 foreach (var scopeToSeed in _seedDataConfig.Scopes)
//                 {
//                     if (await scopeManager.FindByNameAsync(scopeToSeed.Name, cancellationToken) == null)
//                     {
//                         var descriptor = new OpenIddictScopeDescriptor
//                         {
//                             Name = scopeToSeed.Name,
//                             DisplayName = scopeToSeed.DisplayName ?? scopeToSeed.Name,
//                             Description = scopeToSeed.Description
//                         };

//                         if (scopeToSeed.Resources.Any())
//                         {
//                             descriptor.Resources.UnionWith(scopeToSeed.Resources);
//                         }

//                         await scopeManager.CreateAsync(descriptor, cancellationToken);
//                         _logger.LogInformation("Created custom scope: {ScopeName}", scopeToSeed.Name);
//                     }
//                     else
//                     {
//                         _logger.LogDebug("Custom scope {ScopeName} already exists.", scopeToSeed.Name);
//                     }
//                 }
//             }

//             // Seed Applications
//             if (_seedDataConfig.Applications != null)
//             {
//                 foreach (var appToSeed in _seedDataConfig.Applications)
//                 {
//                     var existingApplicationObject = await applicationManager.FindByClientIdAsync(appToSeed.ClientId, cancellationToken);

//                     if (existingApplicationObject != null)
//                     {
//                         _logger.LogInformation("Application {ClientId} already exists. Deleting and re-creating for seed consistency.", appToSeed.ClientId);
//                         await applicationManager.DeleteAsync(existingApplicationObject, cancellationToken);
//                         existingApplicationObject = null;
//                     }

//                     if (existingApplicationObject == null)
//                     {
//                         var descriptor = new OpenIddictApplicationDescriptor
//                         {
//                             ClientId = appToSeed.ClientId,
//                             ClientSecret = appToSeed.ClientSecret,
//                             DisplayName = appToSeed.DisplayName,
//                             ClientType = appToSeed.ClientType,
//                             ApplicationType = appToSeed.ApplicationType // Ensure this is in appsettings if used
//                         };
//                         // Log what's being set for ClientType and if ClientSecret has a value
//                         _logger.LogInformation("Preparing to create/seed client {ClientId} with ClientType: {ClientType}, ApplicationType: {ApplicationType}, ClientSecret presence: {HasSecret}",
//                             descriptor.ClientId, descriptor.ClientType, descriptor.ApplicationType, !string.IsNullOrEmpty(descriptor.ClientSecret));

//                         descriptor.RedirectUris.UnionWith(appToSeed.RedirectUris.Select(uri => new Uri(uri)));
//                         descriptor.PostLogoutRedirectUris.UnionWith(appToSeed.PostLogoutRedirectUris.Select(uri => new Uri(uri)));
//                         descriptor.Permissions.UnionWith(appToSeed.Permissions);
//                         descriptor.Requirements.UnionWith(appToSeed.Requirements);

//                         // --- FIX FOR SETTINGS ---
//                         if (appToSeed.Settings != null)
//                         {
//                             foreach (var setting in appToSeed.Settings)
//                             {
//                                 string? settingValue = ConvertJsonElementToString(setting.Value, appToSeed.ClientId, setting.Key, _logger);
// #pragma warning disable CS8601 // Possible null reference assignment.
//                                 descriptor.Settings[setting.Key] = settingValue;
// #pragma warning restore CS8601 // Possible null reference assignment.
//                             }
//                         }
//                         // --- END FIX FOR SETTINGS ---

//                         if (appToSeed.Properties != null)
//                         {
//                             // Filter out "ProviderId" if it was previously stored here as a workaround
//                             var filteredProperties = appToSeed.Properties.Where(p => p.Key != "ProviderId");
//                             foreach (var prop in filteredProperties)
//                             {
//                                 descriptor.Properties[prop.Key] = prop.Value;
//                             }
//                         }

//                         // Create the application shell using the descriptor
//                         var newApplicationObject = await applicationManager.CreateAsync(descriptor, cancellationToken);
//                         _logger.LogInformation("Created application shell for: {ClientId}", appToSeed.ClientId);

//                         // --- Link to Provider if ProviderShortCode is specified ---
//                         if (newApplicationObject is AppCustomOpenIddictApplication customApp) // Cast to our custom type
//                         {
//                             if (!string.IsNullOrEmpty(appToSeed.ProviderShortCode))
//                             {
//                                 // Find the provider by its unique ShortCode
//                                 var provider = await dbContext.Providers
//                                     .FirstOrDefaultAsync(p => p.ShortCode == appToSeed.ProviderShortCode, cancellationToken);

//                                 if (provider != null)
//                                 {
//                                     customApp.ProviderId = provider.Id;
//                                     // Persist the change (ProviderId) to the database
//                                     await applicationManager.UpdateAsync(customApp, cancellationToken);
//                                     _logger.LogInformation("Successfully linked application {ClientId} to Provider '{ProviderShortCode}' (ID: {ProviderId})",
//                                         customApp.ClientId, provider.ShortCode, provider.Id);
//                                 }
//                                 else
//                                 {
//                                     _logger.LogWarning("Provider with ShortCode '{ProviderShortCode}' not found for application {ClientId}. ProviderId not set.",
//                                         appToSeed.ProviderShortCode, appToSeed.ClientId);
//                                 }
//                             }
//                             else
//                             {
//                                 _logger.LogInformation("Application {ClientId} does not have a ProviderShortCode specified. No provider link will be made.", customApp.ClientId);
//                             }
//                         }
//                         else
//                         {
//                             // This should ideally not happen if ReplaceDefaultEntities is working correctly.
//                             _logger.LogWarning("Created application {ClientId} is NOT of type AppCustomOpenIddictApplication. Cannot set ProviderId. Actual type: {ActualType}",
//                                 appToSeed.ClientId, newApplicationObject?.GetType().FullName);
//                         }
//                         // --- End Link to Provider ---
//                     }
//                     else
//                     {
//                         // This case should ideally not be reached if existingApplication was deleted above.
//                         _logger.LogDebug("Application {ClientId} already exists and was not re-created (unexpected).", appToSeed.ClientId);
//                     }
//                 }
//             }
//             _logger.LogInformation("OpenIddict data seeding finished.");
//         }
//         private async Task SeedAdminRoleAndUserAsync(
//             UserManager<ApplicationUser> userManager,
//             RoleManager<ApplicationRole> roleManager,
//             CancellationToken cancellationToken)
//         {
//             const string adminRoleName = "IDPAdmin";
//             // Get admin user details from configuration (appsettings.Development.json or User Secrets)
//             // This is more secure than hardcoding credentials.
//             var adminEmail = _configuration["SeedAdminUser:Email"] ?? "admin@orjnz.com";
//             var adminPassword = _configuration["SeedAdminUser:Password"] ?? "P@$$wOrd123!"; // Fallback default, but use config!
//             var adminFirstName = _configuration["SeedAdminUser:FirstName"] ?? "Admin";
//             var adminLastName = _configuration["SeedAdminUser:LastName"] ?? "User";

//             // 1. Ensure "IDPAdmin" role exists
//             if (!await roleManager.RoleExistsAsync(adminRoleName))
//             {
//                 // var roleResult = await roleManager.CreateAsync(new ApplicationRole(adminRoleName, "Identity Provider Administrator"));
//                 // New - ID is explicitly set
//                 var adminRole = new ApplicationRole(adminRoleName, "Identity Provider Administrator")
//                 {
//                     Id = Guid.NewGuid().ToString() // Explicitly set the ID
//                 };
//                 var roleResult = await roleManager.CreateAsync(adminRole);
//                 if (roleResult.Succeeded)
//                 {
//                     _logger.LogInformation("Created role: {RoleName}", adminRoleName);
//                 }
//                 else
//                 {
//                     _logger.LogError("Failed to create role {RoleName}: {Errors}", adminRoleName, string.Join(", ", roleResult.Errors.Select(e => e.Description)));
//                     return; // Stop if role creation fails
//                 }
//             }
//             else
//             {
//                 _logger.LogDebug("Role {RoleName} already exists.", adminRoleName);
//             }

//             // 2. Ensure Admin user exists and is in the "IDPAdmin" role
//             var adminUser = await userManager.FindByEmailAsync(adminEmail);
//             if (adminUser == null)
//             {
//                 adminUser = new ApplicationUser
//                 {
//                     Id = Guid.NewGuid().ToString(), // Set ID explicitly
//                     UserName = adminEmail,
//                     Email = adminEmail,
//                     FirstName = adminFirstName,
//                     LastName = adminLastName,
//                     EmailConfirmed = true, // Confirm email for seeded admin
//                     LockoutEnabled = false // Typically false for a root admin
//                 };
//                 var userResult = await userManager.CreateAsync(adminUser, adminPassword);
//                 if (userResult.Succeeded)
//                 {
//                     _logger.LogInformation("Created admin user: {AdminEmail}", adminEmail);
//                 }
//                 else
//                 {
//                     _logger.LogError("Failed to create admin user {AdminEmail}: {Errors}", adminEmail, string.Join(", ", userResult.Errors.Select(e => e.Description)));
//                     return; // Stop if user creation fails
//                 }
//             }
//             else
//             {
//                 _logger.LogDebug("Admin user {AdminEmail} already exists.", adminEmail);
//                 // Optionally ensure EmailConfirmed is true if it wasn't before
//                 if (!adminUser.EmailConfirmed)
//                 {
//                     var token = await userManager.GenerateEmailConfirmationTokenAsync(adminUser);
//                     await userManager.ConfirmEmailAsync(adminUser, token);
//                     _logger.LogInformation("Confirmed email for existing admin user {AdminEmail}.", adminEmail);
//                 }
//             }

//             // 3. Assign user to role if not already assigned
//             if (!await userManager.IsInRoleAsync(adminUser, adminRoleName))
//             {
//                 var addToRoleResult = await userManager.AddToRoleAsync(adminUser, adminRoleName);
//                 if (addToRoleResult.Succeeded)
//                 {
//                     _logger.LogInformation("Assigned user {AdminEmail} to role {RoleName}", adminEmail, adminRoleName);
//                 }
//                 else
//                 {
//                     _logger.LogError("Failed to assign user {AdminEmail} to role {RoleName}: {Errors}", adminEmail, adminRoleName, string.Join(", ", addToRoleResult.Errors.Select(e => e.Description)));
//                 }
//             }
//             else
//             {
//                 _logger.LogDebug("Admin user {AdminEmail} is already in role {RoleName}.", adminEmail, adminRoleName);
//             }
//         }

//         // Helper method for seeding standard scopes to avoid repetition
//         private async Task SeedStandardScopeAsync(
//             IOpenIddictScopeManager manager,
//             string scopeName,
//             string displayName,
//             string? description,
//             CancellationToken cancellationToken)
//         {
//             if (await manager.FindByNameAsync(scopeName, cancellationToken) == null)
//             {
//                 await manager.CreateAsync(new OpenIddictScopeDescriptor
//                 {
//                     Name = scopeName,
//                     DisplayName = displayName,
//                     Description = description
//                     // Standard OIDC scopes typically don't have predefined 'Resources' in the same way
//                     // API scopes do, unless you want to tie them to a UserInfo endpoint resource.
//                     // Often, they are just markers for sets of claims.
//                 }, cancellationToken);
//                 _logger.LogInformation("Created standard scope: {ScopeName}", scopeName);
//             }
//             else
//             {
//                 _logger.LogDebug("Standard scope {ScopeName} already exists.", scopeName);
//             }
//         }

//         // Helper for JsonElement to string conversion
//         private static string? ConvertJsonElementToString(JsonElement element, string clientId, string key, ILogger logger)
//         {
//             switch (element.ValueKind)
//             {
//                 case JsonValueKind.String:
//                     return element.GetString();
//                 case JsonValueKind.Number:
//                     return element.GetRawText(); // Or .ToString()
//                 case JsonValueKind.True:
//                     return "true";
//                 case JsonValueKind.False:
//                     return "false";
//                 case JsonValueKind.Null:
//                 case JsonValueKind.Undefined:
//                     return null;
//                 default:
//                     // For arrays or objects, decide on a string representation or log a warning
//                     logger.LogWarning("Setting '{Key}' for client '{ClientId}' has a complex type '{ValueKind}' and will be stored as raw JSON string.",
//                         key, clientId, element.ValueKind);
//                     return element.GetRawText(); // Store as raw JSON string
//             }
//         }

//         public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
//     }
// }
