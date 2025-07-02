
// File: Orjnz.IdentityProvider.Web/Infrastructure/SeedDataConfiguration.cs
using System.Collections.Generic;
using System.Text.Json; // For JsonElement

namespace Orjnz.IdentityProvider.Web.Infrastructure
{
    public class SeedDataConfiguration
    {
        public List<SeedProvider> Providers { get; set; } = new List<SeedProvider>(); // Added for provider seeding
        public List<SeedApplication> Applications { get; set; } = new List<SeedApplication>();
        public List<SeedScope> Scopes { get; set; } = new List<SeedScope>();
    }

    // New class for seeding providers
    public class SeedProvider
    {
        public required string Name { get; set; }
        public required string ShortCode { get; set; } // This must be unique
        public string? WebsiteDomain { get; set; }
        public bool IsActive { get; set; } = true;
        // If you need to pre-define GUIDs for providers in settings (less common for dynamic seeding)
        // public string? Id { get; set; }
    }

    public class SeedApplication
    {
        public required string ClientId { get; set; }
        public string? ClientSecret { get; set; } // For confidential clients
        public required string DisplayName { get; set; }
        public string? ClientType { get; set; } // e.g., Public, Confidential
        public string? ApplicationType { get; set; } // e.g., Web, Native
        public List<string> RedirectUris { get; set; } = new List<string>();
        public List<string> PostLogoutRedirectUris { get; set; } = new List<string>();
        public List<string> Permissions { get; set; } = new List<string>();
        public List<string> Requirements { get; set; } = new List<string>();
        public Dictionary<string, JsonElement>? Settings { get; set; }
        public Dictionary<string, JsonElement>? Properties { get; set; }

        // New property to link application to a provider
        public string? ProviderShortCode { get; set; }
    }

    public class SeedScope
    {
        public required string Name { get; set; }
        public string? DisplayName { get; set; }
        public string? Description { get; set; }
        public List<string> Resources { get; set; } = new List<string>();
    }
}
// // File: Orjnz.IdentityProvider.Web/Infrastructure/SeedDataConfiguration.cs (or similar location)
// using System.Collections.Generic;
// using System.Text.Json; // For JsonElement

// namespace Orjnz.IdentityProvider.Web.Infrastructure
// {
//     public class SeedDataConfiguration
//     {
//         public List<SeedApplication> Applications { get; set; } = new List<SeedApplication>();
//         public List<SeedScope> Scopes { get; set; } = new List<SeedScope>();
//     }

//     public class SeedApplication
//     {
//         public required string ClientId { get; set; }
//         public string? ClientSecret { get; set; } // For confidential clients
//         public required string DisplayName { get; set; }
//         public string? ClientType { get; set; } // e.g., Public, Confidential
//         public string? ApplicationType { get; set; } // e.g., Web, Native
//         public List<string> RedirectUris { get; set; } = new List<string>();
//         public List<string> PostLogoutRedirectUris { get; set; } = new List<string>();
//         public List<string> Permissions { get; set; } = new List<string>();
//         public List<string> Requirements { get; set; } = new List<string>();
//         public Dictionary<string, JsonElement>? Settings { get; set; } // For OpenIddictApplicationDescriptor.Settings
//         public Dictionary<string, JsonElement>? Properties { get; set; } // For OpenIddictApplicationDescriptor.Properties
//     }

//     public class SeedScope
//     {
//         public required string Name { get; set; }
//         public string? DisplayName { get; set; }
//         public string? Description { get; set; }
//         public List<string> Resources { get; set; } = new List<string>();
//     }
// }
