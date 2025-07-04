/// <summary>
/// The main entry point for the Orjnz Identity Provider application.
/// This file is responsible for configuring all services, middleware, and application settings.
/// </summary>
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

// --- 1. APPLICATION BUILDER & LOGGING CONFIGURATION ---
var builder = WebApplication.CreateBuilder(args);

// Configure Serilog for structured logging. It reads configuration from appsettings.json,
// allowing for flexible logging levels and sinks (e.g., Console, File, Seq) per environment.
// Enrichers add valuable context like machine name and thread ID to every log event.
builder.Host.UseSerilog((context, services, loggerConfiguration) => loggerConfiguration
    .ReadFrom.Configuration(context.Configuration)
    .Enrich.FromLogContext()
    .Enrich.WithMachineName()
    .Enrich.WithThreadId()
    .Enrich.WithEnvironmentName());


// --- 2. KESTREL SERVER CONFIGURATION (HTTPS) ---
// Configures the Kestrel web server to use a specific PFX certificate for HTTPS.
// This is crucial for production deployments where the application handles SSL/TLS termination directly,
// rather than relying on a reverse proxy like Nginx or IIS.
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.ConfigureHttpsDefaults(listenOptions =>
    {
        var pfxPath = builder.Configuration["Kestrel:Certificates:Default:Path"];
        var pfxPassword = builder.Configuration["Kestrel:Certificates:Default:Password"];

        if (!string.IsNullOrEmpty(pfxPath) && !string.IsNullOrEmpty(pfxPassword))
        {
            // Load the certificate from the specified path and password.
            listenOptions.ServerCertificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(pfxPath, pfxPassword);
            Log.Information("Kestrel HTTPS configured with PFX certificate from {PfxPath}", pfxPath);
        }
        else if (builder.Environment.IsDevelopment())
        {
            // In development, if a PFX is not configured, ASP.NET Core will automatically
            // fall back to the local development certificate (`dotnet dev-certs https`).
            Log.Information("Kestrel PFX certificate not configured. Falling back to default ASP.NET Core development certificate.");
        }
    });
});

// --- 3. DATABASE & ENTITY FRAMEWORK CORE CONFIGURATION ---
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    // Configure Entity Framework Core to use PostgreSQL as the database provider.
    options.UseNpgsql(connectionString);

    // Configure OpenIddict to use our custom entity models. This is a critical step
    // that allows us to add custom properties to OpenIddict's default tables (e.g., adding ProviderId to Applications).
    options.UseOpenIddict<
        AppCustomOpenIddictApplication,
        AppCustomOpenIddictAuthorization,
        AppCustomOpenIddictScope,
        AppCustomOpenIddictToken,
        string>(); // The key type is string.
});

// Provides detailed database-related error pages in development.
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

// --- 4. ASP.NET CORE IDENTITY CONFIGURATION ---
// Configures the Identity system with our custom ApplicationUser and ApplicationRole classes.
builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
    {
        // Security policy: Users must confirm their email before they can sign in.
        options.SignIn.RequireConfirmedAccount = true;

        // Password complexity requirements for enhanced security.
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequiredLength = 8;

        // User settings: Enforces unique email addresses across all accounts.
        options.User.RequireUniqueEmail = true;

        // Lockout settings: Protects against brute-force attacks.
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.AllowedForNewUsers = true;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>() // Persists Identity data to the database via ApplicationDbContext.
    .AddDefaultTokenProviders(); // Enables generation of tokens for password resets, email confirmations, etc.

// --- 5. APPLICATION COOKIE CONFIGURATION ---
// Configures the behavior of the authentication cookie used for interactive browser sessions.
builder.Services.ConfigureApplicationCookie(options =>
{
    // When an unauthenticated user tries to access a protected resource, they are redirected to this path.
    options.LoginPath = "/Identity/Account/Login";
    // The path to handle user logout.
    options.LogoutPath = "/Identity/Account/Logout";
    // The path shown when a user is authenticated but not authorized to view a resource.
    options.AccessDeniedPath = "/Identity/Account/AccessDenied";
});

// --- 6. SERVICE & DEPENDENCY INJECTION REGISTRATION ---
// Register application services with the dependency injection container.

// Service for sending emails (e.g., for account confirmation).
builder.Services.AddTransient<IEmailSender, EmailSender>();
// Binds the "SmtpSettings" section from appsettings.json to the SmtpSettings class.
builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("SmtpSettings"));

// Caching Services (using in-memory for simplicity).
// For production, a distributed cache like Redis is recommended for multi-server deployments.
builder.Services.AddMemoryCache();
builder.Services.AddDistributedMemoryCache();

// Registers the custom service for generating and validating confirmation codes.
builder.Services.AddConfirmationCodeService();

builder.Services.AddRazorPages();

// --- 7. QUARTZ.NET SCHEDULER CONFIGURATION ---
// OpenIddict uses Quartz.NET for background tasks, primarily to clean up expired tokens and authorizations from the database.
builder.Services.AddQuartz(options =>
{
    options.UseSimpleTypeLoader();
    // For development, an in-memory store is sufficient.
    // For production, a persistent store (like JDBC with PostgreSQL) is required to ensure jobs are not lost on application restart.
    options.UseInMemoryStore();
});
// Ensures the application waits for scheduled jobs to complete before shutting down.
builder.Services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

// --- 8. CUSTOM APPLICATION SERVICE REGISTRATION ---
// Registers core business logic services with a scoped lifetime, meaning one instance per HTTP request.
builder.Services.AddScoped<IUserAuthenticationService, UserAuthenticationService>();
builder.Services.AddScoped<IClientApplicationService, ClientApplicationService>();
builder.Services.AddScoped<IConsentService, ConsentService>();
builder.Services.AddScoped<IScopeValidationService, ScopeValidationService>();
builder.Services.AddScoped<IClaimsGenerationService, ClaimsGenerationService>();
builder.Services.AddScoped<IAuthorizationPersistenceService, AuthorizationPersistenceService>();

// --- 9. DATABASE SEEDER CONFIGURATION ---
// Configures and registers the DataSeeder, which runs on startup to populate the database
// with initial data (default clients, scopes, admin users) from appsettings.json.
builder.Services.Configure<SeedDataConfiguration>(builder.Configuration.GetSection("OpenIddictSeedData"));
builder.Services.AddHostedService<DataSeeder>();

// --- 10. OPENIDDICT AUTHENTICATION SERVER CONFIGURATION ---
builder.Services.AddOpenIddict()

    // --- A. CORE COMPONENTS ---
    .AddCore(options =>
    {
        // Configure OpenIddict to use Entity Framework Core for data persistence.
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>()
               // This links OpenIddict to our custom EF Core entities, enabling extended properties.
               .ReplaceDefaultEntities<
                   AppCustomOpenIddictApplication,
                   AppCustomOpenIddictAuthorization,
                   AppCustomOpenIddictScope,
                   AppCustomOpenIddictToken,
                   string>();

        // Configure OpenIddict to use Quartz.NET for background tasks.
        options.UseQuartz();
    })

    // --- B. SERVER COMPONENTS ---
    .AddServer(options =>
    {
        // Defines the claims that clients can request. These are advertised in the discovery document.
        options.RegisterClaims(
            OpenIddictConstants.Claims.Subject, OpenIddictConstants.Claims.Name,
            OpenIddictConstants.Claims.GivenName, OpenIddictConstants.Claims.FamilyName,
            OpenIddictConstants.Claims.Email, OpenIddictConstants.Claims.EmailVerified,
            OpenIddictConstants.Claims.PhoneNumber, OpenIddictConstants.Claims.PhoneNumberVerified,
            OpenIddictConstants.Claims.Profile, OpenIddictConstants.Claims.PreferredUsername,
            OpenIddictConstants.Claims.Picture, OpenIddictConstants.Claims.Website,
            OpenIddictConstants.Claims.Gender, OpenIddictConstants.Claims.Birthdate,
            OpenIddictConstants.Claims.Zoneinfo, OpenIddictConstants.Claims.Locale,
            OpenIddictConstants.Claims.UpdatedAt, OpenIddictConstants.Claims.Role,
            "provider_id" // Custom claim specific to this application.
        );

        // Defines the scopes that clients can request. These are advertised in the discovery document.
        options.RegisterScopes(
            OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.Email,
            OpenIddictConstants.Scopes.Profile, OpenIddictConstants.Scopes.Phone,
            OpenIddictConstants.Scopes.Address, OpenIddictConstants.Scopes.Roles,
            OpenIddictConstants.Scopes.OfflineAccess // Required for issuing refresh tokens.
        );

        // Configure the OIDC/OAuth2 protocol endpoints. Values are read from appsettings.json for flexibility.
        options.SetAuthorizationEndpointUris(builder.Configuration.GetValue<string>("OpenIddict:Endpoints:Authorization") ?? "/connect/authorize")
               .SetTokenEndpointUris(builder.Configuration.GetValue<string>("OpenIddict:Endpoints:Token") ?? "/connect/token")
               .SetLogoutEndpointUris(builder.Configuration.GetValue<string>("OpenIddict:Endpoints:Logout") ?? "/connect/logout")
               .SetUserinfoEndpointUris(builder.Configuration.GetValue<string>("OpenIddict:Endpoints:Userinfo") ?? "/connect/userinfo")
               .SetIntrospectionEndpointUris(builder.Configuration.GetValue<string>("OpenIddict:Endpoints:Introspection") ?? "/connect/introspect")
               .SetDeviceEndpointUris(builder.Configuration.GetValue<string>("OpenIddict:Endpoints:Device") ?? "/connect/device")
               .SetVerificationEndpointUris(builder.Configuration.GetValue<string>("OpenIddict:Endpoints:Verification") ?? "/connect/verify");

        // Enable the supported OAuth 2.0 flows.
        options.AllowAuthorizationCodeFlow()  // For confidential clients (e.g., web apps) and public clients (e.g., SPAs, mobile apps) with PKCE.
               .AllowRefreshTokenFlow()        // Allows clients to obtain new access tokens without re-authenticating the user.
               .AllowClientCredentialsFlow()   // For machine-to-machine communication.
               .AllowDeviceCodeFlow();        // For input-constrained devices (e.g., Smart TVs).
        
        // PKCE (Proof Key for Code Exchange) is automatically enforced for public clients, which is a critical security measure.

        // Register signing and encryption credentials for tokens.
        var pfxPath = builder.Configuration.GetValue<string>("OpenIddict:Certificates:Path");
        var pfxPassword = builder.Configuration.GetValue<string>("OpenIddict:Certificates:Password");

        if (!string.IsNullOrEmpty(pfxPath) && System.IO.File.Exists(pfxPath))
        {
            // PRODUCTION: Load certificate from PFX file for signing and encrypting tokens.
            Log.Information("Loading OpenIddict certificate from PFX: {PfxPath}", pfxPath);
            var certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(pfxPath, pfxPassword,
                System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.MachineKeySet |
                System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.PersistKeySet |
                System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);

            options.AddSigningCertificate(certificate);
            options.AddEncryptionCertificate(certificate);
        }
        else if (builder.Environment.IsDevelopment())
        {
            // DEVELOPMENT: Use ephemeral in-memory certificates. Not suitable for production.
            Log.Warning("OpenIddict PFX certificate not found at {PfxPath}. Falling back to development certificates.", pfxPath);
            options.AddDevelopmentEncryptionCertificate();
            options.AddDevelopmentSigningCertificate();
        }
        else
        {
            // PRODUCTION ERROR: A certificate is mandatory in production.
            throw new InvalidOperationException($"OpenIddict PFX certificate not found at '{pfxPath}' and not in development environment. Certificate is required for production.");
        }

        // Configure ASP.NET Core integration.
        options.UseAspNetCore()
               .EnableStatusCodePagesIntegration() // Provides standardized OIDC error responses.
               .EnableAuthorizationEndpointPassthrough() // Allows Razor Pages/MVC to handle the /connect/authorize request.
               .EnableLogoutEndpointPassthrough()      // Allows Razor Pages/MVC to handle the /connect/logout request.
               .EnableUserinfoEndpointPassthrough()    // Allows a custom controller/handler for the /connect/userinfo request.
               .EnableVerificationEndpointPassthrough();

        // Disables access token encryption. Access tokens will be standard signed JWTs instead of encrypted JWEs.
        // This is a common choice when resource APIs are within a trusted boundary and can perform local JWT validation,
        // which is simpler than decrypting a JWE. The token is still protected by TLS during transit.
        options.DisableAccessTokenEncryption();

        // --- Custom Event Handlers ---
        // Register a custom handler to populate claims in the UserInfo response.
        // This gives us full control over what data is returned from the UserInfo endpoint.
        options.AddEventHandler<OpenIddictServerEvents.HandleUserinfoRequestContext>(builder =>
        {
            builder.UseScopedHandler<UserInfoHandler>();
        });
        
        // Register an inline handler for logging token requests. This is excellent for debugging OIDC flows.
        // It's configured to run before the main token request handler.
        options.AddEventHandler<OpenIddictServerEvents.HandleTokenRequestContext>(builder =>
            builder.UseInlineHandler(async context =>
            {
                var httpContext = context.Transaction.GetHttpRequest()?.HttpContext;
                if (httpContext is null) return;
                var logger = httpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                
                logger.LogInformation("--- TOKEN ENDPOINT REQUEST (IDP DEBUG) ---");
                logger.LogInformation("Grant Type: {GrantType}, Client ID: {ClientId}", context.Request.GrantType, context.Request.ClientId);
                logger.LogInformation("PKCE Verifier Present: {HasCodeVerifier}", !string.IsNullOrEmpty(context.Request.CodeVerifier));
                
                httpContext.Request.EnableBuffering();
                using var reader = new StreamReader(httpContext.Request.Body, System.Text.Encoding.UTF8, leaveOpen: true);
                var body = await reader.ReadToEndAsync();
                httpContext.Request.Body.Position = 0;
                logger.LogInformation("Request Body (Form Data): {Body}", body);
                logger.LogInformation("--- END TOKEN ENDPOINT REQUEST (IDP DEBUG) ---");
            })
            .SetOrder(OpenIddictServerHandlers.Exchange.HandleTokenRequest.Descriptor.Order - 500)
        );
    })

    // --- C. VALIDATION COMPONENTS ---
    // Configures this server to also be able to validate its own tokens.
    // This is required for protecting endpoints like UserInfo and Introspection.
    .AddValidation(options =>
    {
        // Use the local server's own configuration for token validation (issuer, signing keys).
        options.UseLocalServer();

        // Register the ASP.NET Core host integration.
        options.UseAspNetCore();

        // Enables a check to ensure access tokens are automatically invalidated
        // if the underlying authorization entry is revoked.
        options.EnableAuthorizationEntryValidation();
    });

// --- 11. CORS & AUTHORIZATION POLICIES ---
// Configure Cross-Origin Resource Sharing (CORS) to allow requests from the Next.js client.
var nextJsClientOrigin = builder.Configuration.GetValue<string>("AllowedOrigins:NextJsClient") ?? "http://localhost:3000";
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins(nextJsClientOrigin)
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

// Define authorization policies for securing different parts of the application.
builder.Services.AddAuthorization(options =>
{
    // This policy requires a user to be authenticated and have the "IDPAdmin" role.
    options.AddPolicy("IDPAdminPolicy", policy =>
        policy.RequireAuthenticatedUser()
              .RequireRole("IDPAdmin"));
});

// Apply the authorization policy to the entire "/Admin" area.
builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizeAreaFolder("Admin", "/", "IDPAdminPolicy");
});

// --- 12. APPLICATION PIPELINE CONFIGURATION ---
var app = builder.Build();

Log.Information("Application Starting Up...");

// Add Serilog's request logging middleware to log all incoming HTTP requests.
app.UseSerilogRequestLogging();

// Configure the HTTP request pipeline. Order is critical.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error");
    // Use HTTP Strict Transport Security (HSTS) in production.
    app.UseHsts();
}

// Redirects HTTP requests to HTTPS.
app.UseHttpsRedirection();

// Enables serving static files (e.g., CSS, JavaScript, images) from the wwwroot folder.
app.UseStaticFiles();

// Adds route matching to the pipeline.
app.UseRouting();

// Applies the configured CORS policy to incoming requests. Must be placed after UseRouting and before UseAuthentication/UseAuthorization.
app.UseCors();

// Adds the authentication and authorization middleware to the pipeline.
// UseAuthentication attempts to identify the user from the incoming request (e.g., via cookie).
app.UseAuthentication();
// UseAuthorization checks if the identified user is permitted to access the requested resource.
app.UseAuthorization();

// Maps Razor Pages endpoints.
app.MapRazorPages();

// Run the application.
app.Run();