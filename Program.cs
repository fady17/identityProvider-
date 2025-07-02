
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Orjnz.IdentityProvider.Web.Data;
using Orjnz.IdentityProvider.Web.Infrastructure;
using Orjnz.IdentityProvider.Web.Services;
using Quartz;
using Serilog;
using OpenIddict.Server.AspNetCore;
using Microsoft.AspNetCore;
using Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities;
// using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);
// var loggerConfig = new LoggerConfiguration()
//     .ReadFrom.Configuration(builder.Configuration)
//     .Enrich.FromLogContext()
//     .Enrich.WithMachineName()
//     .Enrich.WithThreadId()
//     .Enrich.WithEnvironmentName()
//     .WriteTo.Console();

// // Only add Seq if URL is configured
// var seqUrl = builder.Configuration["Serilog:SeqServerUrl"];
// if (!string.IsNullOrEmpty(seqUrl))
// {
//     loggerConfig.WriteTo.Seq(seqUrl);
// }

// Log.Logger = loggerConfig.CreateBootstrapLogger();
// builder.Host.UseSerilog(); 
builder.Host.UseSerilog((context, services, loggerConfiguration) => loggerConfiguration
    .ReadFrom.Configuration(context.Configuration) // This will read "Serilog" section from appsettings.json
                                                    // Ensure your appsettings.json has "Serilog:MinimumLevel",
                                                    // "Serilog:WriteTo:Console", "Serilog:WriteTo:Seq" etc.
    .Enrich.FromLogContext()
    .Enrich.WithMachineName()
    .Enrich.WithThreadId()
    .Enrich.WithEnvironmentName());


// --- Configure Kestrel to use the PFX certificate ---
// This is usually done if not using IIS or another reverse proxy for HTTPS termination.
// If deploying behind Nginx that handles HTTPS, Kestrel might listen on HTTP locally.
// For local development and self-hosted VPS, direct Kestrel HTTPS is common.
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.ConfigureHttpsDefaults(listenOptions =>
    {
        // Path to your PFX file
        var pfxPath = builder.Configuration["Kestrel:Certificates:Default:Path"];
        // Password for your PFX file
        var pfxPassword = builder.Configuration["Kestrel:Certificates:Default:Password"];

        if (!string.IsNullOrEmpty(pfxPath) && !string.IsNullOrEmpty(pfxPassword))
        {
            listenOptions.ServerCertificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(pfxPath, pfxPassword);
            Log.Information("Kestrel HTTPS configured with PFX certificate from {PfxPath}", pfxPath); // Assuming _logger is available or use Console.WriteLine
        }
        else if (builder.Environment.IsDevelopment())
        {
            // Fallback to development certificate if PFX not configured in dev
            // This is often handled by default `UseHttpsRedirection()` and launchSettings
          Log.Information("Kestrel PFX certificate not configured. Kestrel may use default ASP.NET Core development certificate.");
        }
    });
});
// --- End Kestrel Configuration ---

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseNpgsql(connectionString);
    options.UseOpenIddict<
        AppCustomOpenIddictApplication,
        AppCustomOpenIddictAuthorization,
        AppCustomOpenIddictScope,
        AppCustomOpenIddictToken,
        string>();

    // options.UseOpenIddict();
});
builder.Services.AddDatabaseDeveloperPageExceptionFilter();



builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options => // Specify both custom types
    {
         options.SignIn.RequireConfirmedAccount = true;
        // Password settings
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequiredLength = 8; 

        // User settings
        options.User.RequireUniqueEmail = true;

        // Lockout settings
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.AllowedForNewUsers = true;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders(); // For password reset, email confirmation tokens etc.

// === \VERIFY THIS SECTION ===
builder.Services.ConfigureApplicationCookie(options =>
{
    // This is the path where your scaffolded login page is located.
    options.LoginPath = "/Identity/Account/Login";
    options.LogoutPath = "/Identity/Account/Logout"; // Also ensure this matches your scaffolded logout
    options.AccessDeniedPath = "/Identity/Account/AccessDenied"; // And this for access denied
    // options.ReturnUrlParameter = "ReturnUrl"; // This is the default, usually no need to change
});
// === END SECTION ===


builder.Services.AddTransient<IEmailSender, EmailSender>();
// Configure SmtpSettings from appsettings.json
builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("SmtpSettings"));

//TODO: Redis Cache (for production/multi-server)
// builder.Services.AddStackExchangeRedisCache(options =>
// {
//     options.Configuration = builder.Configuration.GetConnectionString("Redis");
// });


builder.Services.AddMemoryCache();
builder.Services.AddDistributedMemoryCache();

// Register the confirmation code service
builder.Services.AddConfirmationCodeService();

builder.Services.AddRazorPages();



//TODO:
// builder.Services.Configure<ForwardedHeadersOptions>(options =>
// {
//     options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
//     // options.KnownNetworks.Clear(); // Only if Nginx is not on localhost
//     // options.KnownProxies.Clear();  // Only if Nginx is not on localhost
// });
// --- QUARTZ.NET Configuration (for OpenIddict scheduled tasks) ---
builder.Services.AddQuartz(options =>
{
    options.UseSimpleTypeLoader();
    options.UseInMemoryStore(); // For development; consider a persistent store for production (e.g., JDBC with PostgreSQL)
});
// Register the Quartz.NET service and configure it to block shutdown until jobs are complete.
builder.Services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

builder.Services.AddScoped<IUserAuthenticationService, UserAuthenticationService>();
builder.Services.AddScoped<IClientApplicationService, ClientApplicationService>();
builder.Services.AddScoped<IConsentService, ConsentService>();
builder.Services.AddScoped<IScopeValidationService, ScopeValidationService>();
builder.Services.AddScoped<IClaimsGenerationService, ClaimsGenerationService>();
builder.Services.AddScoped<IAuthorizationPersistenceService, AuthorizationPersistenceService>();

// Configuration for Seeder
builder.Services.Configure<SeedDataConfiguration>(builder.Configuration.GetSection("OpenIddictSeedData"));
builder.Services.AddHostedService<DataSeeder>();


// === OPENIDDICT CONFIGURATION ===
builder.Services.AddOpenIddict()

    // Register the OpenIddict core components.
    .AddCore(options =>
    {
        // Configure OpenIddict to use the Entity Framework Core stores and models.
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>()
               .ReplaceDefaultEntities<
                   AppCustomOpenIddictApplication,
                   AppCustomOpenIddictAuthorization,
                   AppCustomOpenIddictScope,
                   AppCustomOpenIddictToken,
                   string>();

        // Configure OpenIddict to use Quartz.NET to perform scheduled tasks.
        options.UseQuartz();
    })

    // Register the OpenIddict server components.
    .AddServer(options =>
    {
        // Define the list of public OIDC claims that can be requested by clients
        // (This will be advertised in the discovery document)
        options.RegisterClaims(
            OpenIddictConstants.Claims.Subject,
            OpenIddictConstants.Claims.Name,
            OpenIddictConstants.Claims.GivenName,
            OpenIddictConstants.Claims.FamilyName,
            OpenIddictConstants.Claims.Email,
            OpenIddictConstants.Claims.EmailVerified,
            OpenIddictConstants.Claims.PhoneNumber,
            OpenIddictConstants.Claims.PhoneNumberVerified,
            OpenIddictConstants.Claims.Profile,
            OpenIddictConstants.Claims.PreferredUsername,
            OpenIddictConstants.Claims.Picture,
            OpenIddictConstants.Claims.Website,
            OpenIddictConstants.Claims.Gender,
            OpenIddictConstants.Claims.Birthdate,
            OpenIddictConstants.Claims.Zoneinfo,
            OpenIddictConstants.Claims.Locale,
            OpenIddictConstants.Claims.UpdatedAt,
            OpenIddictConstants.Claims.Role, // For standard role claim
            "provider_id" // Our custom claim
                          // Add other custom claims you plan to issue
        );

        // Define the list of public OIDC scopes that can be requested by clients
        // (This will be advertised in the discovery document)
        options.RegisterScopes(
            OpenIddictConstants.Scopes.OpenId,
            OpenIddictConstants.Scopes.Email,
            OpenIddictConstants.Scopes.Profile,
            OpenIddictConstants.Scopes.Phone,
            OpenIddictConstants.Scopes.Address,
            OpenIddictConstants.Scopes.Roles, // Standard scope for roles
            OpenIddictConstants.Scopes.OfflineAccess // For refresh tokens
                                                     // Add custom API scopes later, e.g., "gis-api", "clinic-api"
        );

        // Configure the endpoints.
        // For OpenIddict 5.x:
        options.SetAuthorizationEndpointUris(builder.Configuration.GetValue<string>("OpenIddict:Endpoints:Authorization") ?? "/connect/authorize")
               .SetTokenEndpointUris(builder.Configuration.GetValue<string>("OpenIddict:Endpoints:Token") ?? "/connect/token")
               .SetLogoutEndpointUris(builder.Configuration.GetValue<string>("OpenIddict:Endpoints:Logout") ?? "/connect/logout")
               .SetUserinfoEndpointUris(builder.Configuration.GetValue<string>("OpenIddict:Endpoints:Userinfo") ?? "/connect/userinfo")
               .SetIntrospectionEndpointUris(builder.Configuration.GetValue<string>("OpenIddict:Endpoints:Introspection") ?? "/connect/introspect")
               .SetDeviceEndpointUris(builder.Configuration.GetValue<string>("OpenIddict:Endpoints:Device") ?? "/connect/device") // If supporting device flow
               .SetVerificationEndpointUris(builder.Configuration.GetValue<string>("OpenIddict:Endpoints:Verification") ?? "/connect/verify"); // For device flow user interaction



        // Enable the flows you want to support.
        options.AllowAuthorizationCodeFlow()
               .AllowRefreshTokenFlow()
               .AllowClientCredentialsFlow()
               .AllowDeviceCodeFlow();
        // .AllowDeviceCodeFlow(); // If supporting device flow
        // .AllowImplicitFlow(); // Not recommended for new applications

        // PKCE is enforced by default for public clients using the authorization code flow.

        // options.RequireProofKeyForCodeExchange();

        // Register the signing and encryption credentials.
        // FOR DEVELOPMENT ONLY:
        // options.AddDevelopmentEncryptionCertificate()
        //        .AddDevelopmentSigningCertificate();
        // TODO: For PRODUCTION, replace with robust key management (e.g., X.509 certs from store/Key Vault)
        // options.AddSigningCertificate(LoadCertificateFromStoreOrVault(...));
        // options.AddEncryptionCertificate(LoadCertificateFromStoreOrVault(...));
        // OR if using symmetric key for encryption (for local validation testing as in Zirku):
        // options.AddEncryptionKey(new SymmetricSecurityKey(
        //     Convert.FromBase64String(builder.Configuration["OpenIddict:EncryptionKey"]!)
        // ));

        // --- Use the PFX for OpenIddict Signing & Encryption ---
        var pfxPath = builder.Configuration.GetValue<string>("OpenIddict:Certificates:Path");
        var pfxPassword = builder.Configuration.GetValue<string>("OpenIddict:Certificates:Password");

        if (!string.IsNullOrEmpty(pfxPath) && System.IO.File.Exists(pfxPath))
        {
            Log.Information("Loading OpenIddict certificate from PFX: {PfxPath}", pfxPath); // Assuming _logger is available
            var certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(pfxPath, pfxPassword,
                System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.MachineKeySet | // Or UserKeySet / EphemeralKeySet
                System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.PersistKeySet |
                System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);

            options.AddSigningCertificate(certificate);
            options.AddEncryptionCertificate(certificate); // Using same cert for both is fine for dev/staging
            
            // If you want to ensure tokens are JWS (signed) and not JWE (encrypted+signed) for easier API validation:
            // options.DisableAccessTokenEncryption();
        }
        else if (builder.Environment.IsDevelopment())
        {
            Log.Warning("OpenIddict PFX certificate not found at {PfxPath}. Falling back to development certificates.", pfxPath);
            options.AddDevelopmentEncryptionCertificate();
            options.AddDevelopmentSigningCertificate();
        }
        else // Production
        {
            throw new InvalidOperationException($"OpenIddict PFX certificate not found at '{pfxPath}' and not in development environment. Certificate is required for production.");
        }
        // --- End OpenIddict Certificate Configuration ---


        // Configure ASP.NET Core host integration.
        options.UseAspNetCore()
               .EnableStatusCodePagesIntegration() // Better error responses for OIDC errors
               .EnableAuthorizationEndpointPassthrough()
               .EnableLogoutEndpointPassthrough()
               .EnableUserinfoEndpointPassthrough()
               .EnableVerificationEndpointPassthrough();// If using device flow custom UI
                                                        //    .EnableDeviceEndpointPassthrough(); // If using device flow custom UI
                                                        //    .EnableTokenEndpointPassthrough()

        // TODO: Consider disabling access token encryption if all your APIs
        // will perform local JWT validation and don't require JWEs.
        // This makes tokens opaque only if they are reference tokens.
        // If they are JWTs, they will be signed but not encrypted.
        options.DisableAccessTokenEncryption();
         // --- REGISTERING CUSTOM USERINFO HANDLER ---
        options.AddEventHandler<OpenIddictServerEvents.HandleUserinfoRequestContext>(builder =>
        {
            // Option 1: Replace OpenIddict's default UserInfo response generation.
            // This is often preferred if your handler is comprehensive.
            // OpenIddict has default handlers that might also try to populate claims.
            // To ensure ONLY your handler runs for populating claims from user profile:
       // This is a custom extension method we might need to define or find equivalent
                                            // Or more specifically:
                                            // builder.Remove(OpenIddictServerHandlers.Userinfo.ResolveUserinfoRequest.Descriptor); // Example
                                            // builder.Remove(OpenIddictServerHandlers.Userinfo.GenerateUserinfoResponse.Descriptor); // Example

            builder.UseScopedHandler<UserInfoHandler>(); // Preferred if UserInfoHandler has scoped dependencies


        }
        
        
        );
options.AddEventHandler<OpenIddictServerEvents.HandleTokenRequestContext>(builder =>
    builder.UseInlineHandler(async context =>
    {
        var httpContext = context.Transaction.GetHttpRequest()?.HttpContext;
        if (httpContext is null)
            return;

        var logger = httpContext.RequestServices.GetRequiredService<ILogger<Program>>();

        logger.LogInformation("--- TOKEN ENDPOINT REQUEST ---");
        logger.LogInformation("IDP: Request Path: {Path}", httpContext.Request.Path);
        logger.LogInformation("IDP: Request Method: {Method}", httpContext.Request.Method);
        logger.LogInformation("IDP: Client ID from request: {ClientId}", context.Request.ClientId);
        logger.LogInformation("IDP: Grant Type: {GrantType}", context.Request.GrantType);
        logger.LogInformation("IDP: Code Verifier present?: {HasCodeVerifier}", !string.IsNullOrEmpty(context.Request.CodeVerifier));
        logger.LogInformation("IDP: Authorization Header: {AuthHeader}", httpContext.Request.Headers["Authorization"].FirstOrDefault());

        // Read and log body (non-destructive)
        httpContext.Request.EnableBuffering();
        using var reader = new StreamReader(httpContext.Request.Body, System.Text.Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1024, leaveOpen: true);
        var body = await reader.ReadToEndAsync();
        httpContext.Request.Body.Position = 0;

        logger.LogInformation("IDP: Request Body (first 500 chars): {Body}", body.Substring(0, Math.Min(body.Length, 500)));
        logger.LogInformation("--- END TOKEN ENDPOINT REQUEST ---");
    })
    .SetOrder(OpenIddictServerHandlers.Exchange.HandleTokenRequest.Descriptor.Order - 500)
);
    })

    // Register the OpenIddict validation components.
    // This is for the IDP to protect its own endpoints (e.g., UserInfo, Introspection)
    // or if the IDP itself acts as a resource server for some reason.
    .AddValidation(options =>
    {
        // Import the configuration from the local OpenIddict server instance.
        options.UseLocalServer();

        // Register the ASP.NET Core host.
        options.UseAspNetCore();

        // Enable authorization entry validation. This is important to ensure that
        // access tokens are automatically invalidated if the corresponding authorization entry is revoked.
        options.EnableAuthorizationEntryValidation();
    });

var nextJsClientOrigin = builder.Configuration.GetValue<string>("AllowedOrigins:NextJsClient") ?? "http://localhost:3000";
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy => // Or a named policy like "NextJsClientPolicy"
    {
        policy.WithOrigins(nextJsClientOrigin) // Your Next.js app's development URL
              .AllowAnyHeader()
              .AllowAnyMethod();
              // .AllowCredentials(); // Consider if needed for specific scenarios
    });
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("IDPAdminPolicy", policy =>
        policy.RequireAuthenticatedUser()
              .RequireRole("IDPAdmin"));
});

builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizeAreaFolder("Admin", "/", "IDPAdminPolicy");
});

var app = builder.Build();

Log.Information("Application Starting Up...");
// app.UseForwardedHeaders();
app.UseSerilogRequestLogging();

// --- CLEANUP USERS AND ROLES ON STARTUP (FOR DEVELOPMENT/TESTING ONLY) ---
// using (var scope = app.Services.CreateScope())
// {
//     var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
//     var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
//     var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    
//     // WARNING: This deletes ALL users and roles - use only in development!
//     if (app.Environment.IsDevelopment())
//     {
//         Log.Information("Starting development cleanup: Deleting all users and roles");
        
//         // Delete all users first (this also removes user-role relationships)
//         var allUsers = await userManager.Users.ToListAsync();
//         Log.Information("Found {UserCount} users to delete", allUsers.Count);
        
//         foreach (var user in allUsers)
//         {
//             var result = await userManager.DeleteAsync(user);
//             if (!result.Succeeded)
//             {
//                 Log.Warning("Failed to delete user {UserId}: {Errors}", 
//                     user.Id, string.Join(", ", result.Errors.Select(e => e.Description)));
//             }
//         }
        
//         // Delete all custom roles
//         var allRoles = await roleManager.Roles.ToListAsync();
//         Log.Information("Found {RoleCount} roles to delete", allRoles.Count);
        
//         foreach (var role in allRoles)
//         {
//             var result = await roleManager.DeleteAsync(role);
//             if (!result.Succeeded)
//             {
//                 Log.Warning("Failed to delete role {RoleId}: {Errors}", 
//                     role.Id, string.Join(", ", result.Errors.Select(e => e.Description)));
//             }
//         }
        
//         // Save changes to ensure everything is persisted
//         await dbContext.SaveChangesAsync();
        
//         // Verify cleanup by checking counts
//         var remainingUsers = await userManager.Users.CountAsync();
//         var remainingRoles = await roleManager.Roles.CountAsync();
        
//         Log.Information("Development cleanup completed. Remaining users: {UserCount}, Remaining roles: {RoleCount}", 
//             remainingUsers, remainingRoles);
        
//         // Optional: Clear OpenIddict data as well if you're using it
//         // This removes any stored applications, authorizations, scopes, and tokens
//         // await dbContext.Database.ExecuteSqlRawAsync("DELETE FROM \"OpenIddictTokens\"");
//         // await dbContext.Database.ExecuteSqlRawAsync("DELETE FROM \"OpenIddictAuthorizations\"");
//         // await dbContext.Database.ExecuteSqlRawAsync("DELETE FROM \"OpenIddictScopes\"");
//         // await dbContext.Database.ExecuteSqlRawAsync("DELETE FROM \"OpenIddictApplications\"");
//     }
// }

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseCors();

// Add Authentication and Authorization middleware
app.UseAuthentication();
app.UseAuthorization();


app.MapRazorPages();

app.Run();

// Helper to read request body for logging
// async Task<string> ReadRequestBodyAsync(HttpRequest request)
// {
//     request.EnableBuffering();

//     var buffer = new byte[Math.Min(Convert.ToInt32(request.ContentLength ?? 0), 500)];
//     await request.Body.ReadAsync(buffer, 0, buffer.Length);
//     request.Body.Position = 0;

//     return System.Text.Encoding.UTF8.GetString(buffer);
// }