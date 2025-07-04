using Microsoft.AspNetCore.Mvc.Rendering; // For SelectList
using OpenIddict.Abstractions; // For OpenIddictConstants
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using static OpenIddict.Abstractions.OpenIddictConstants; // For easy access to constants like ClientTypes

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Models
{
    /// <summary>
    /// Represents the view model for creating and editing an OpenIddict client application.
    /// This model serves as an intermediary between the database entity (`AppCustomOpenIddictApplication`)
    /// and the user interface, providing data annotations for validation and properties to populate UI controls.
    /// </summary>
    public class ApplicationViewModel
    {
        /// <summary>
        /// The unique database identifier of the OpenIddict application.
        /// This is null when creating a new application.
        /// </summary>
        public string? Id { get; set; }

        /// <summary>
        /// The public, unique identifier for the client application (`client_id`).
        /// This is used by client applications to identify themselves during an OIDC flow.
        /// </summary>
        [Required(ErrorMessage = "Client ID is required.")]
        [StringLength(100, MinimumLength = 3, ErrorMessage = "Client ID must be between 3 and 100 characters.")]
        [RegularExpression(@"^[a-zA-Z0-9_.\-]+$", ErrorMessage = "Client ID can only contain letters, numbers, underscores, hyphens, and periods.")]
        [Display(Name = "Client ID (Unique Identifier)")]
        public string ClientId { get; set; } = string.Empty;

        /// <summary>
        /// A secret known only to the application and the authorization server.
        /// This is required for "confidential" clients (e.g., server-side web apps) to authenticate themselves.
        /// It should be left empty for "public" clients (e.g., SPAs, mobile apps).
        /// </summary>
        [Display(Name = "Client Secret (for Confidential Clients)")]
        [StringLength(200, ErrorMessage = "Client secret cannot exceed 200 characters.")]
        public string? ClientSecret { get; set; }

        /// <summary>
        /// A user-friendly name for the application, which may be displayed on the consent screen.
        /// </summary>
        [Required(ErrorMessage = "Display name is required.")]
        [StringLength(150, MinimumLength = 3, ErrorMessage = "Display name must be between 3 and 150 characters.")]
        [Display(Name = "Display Name")]
        public string DisplayName { get; set; } = string.Empty;

        /// <summary>
        /// The type of the client, which determines its authentication method.
        /// "Confidential" clients can hold a secret, while "public" clients cannot.
        /// </summary>
        [Required(ErrorMessage = "Client type is required.")]
        [Display(Name = "Client Type")]
        public string ClientType { get; set; } = ClientTypes.Public;

        /// <summary>
        /// An optional property to categorize the application (e.g., "web" or "native").
        /// This is for informational purposes.
        /// </summary>
        [Display(Name = "Application Type (Optional)")]
        public string? ApplicationType { get; set; }

        /// <summary>
        /// The type of consent required from the user.
        /// "Explicit": User is always prompted for consent on first use.
        /// "Implicit": Consent is granted automatically (for trusted first-party apps).
        /// "External": Consent is managed outside the standard flow (e.g., by an admin).
        /// "Systematic": Consent is remembered permanently after the first grant.
        /// </summary>
        [Display(Name = "Consent Type (Optional)")]
        public string? ConsentType { get; set; }

        /// <summary>
        /// A newline-separated list of URLs to which the authorization server is allowed to redirect the user
        /// after successful authentication and consent.
        /// </summary>
        [Display(Name = "Redirect URIs (one per line)")]
        [DataType(DataType.MultilineText)]
        public string? RedirectUris { get; set; }

        /// <summary>
        /// A newline-separated list of URLs to which the authorization server is allowed to redirect the user
        /// after a successful logout.
        /// </summary>
        [Display(Name = "Post-Logout Redirect URIs (one per line)")]
        [DataType(DataType.MultilineText)]
        public string? PostLogoutRedirectUris { get; set; }

        /// <summary>
        /// A list of permissions granted to the client. This controls what the client is allowed to do,
        /// such as which OIDC endpoints it can use (`ept:token`), which flows it can initiate (`grn:authorization_code`),
        /// and which scopes it can request (`scp:profile`).
        /// </summary>
        [Display(Name = "Permissions")]
        public List<string> SelectedPermissions { get; set; } = new List<string>();

        /// <summary>
        /// A list of requirements for the client, such as needing Proof Key for Code Exchange (PKCE).
        /// </summary>
        [Display(Name = "Requirements")]
        public List<string> SelectedRequirements { get; set; } = new List<string>();

        /// <summary>
        /// The foreign key linking this client application to a custom `Provider` entity,
        /// enabling multi-tenancy.
        /// </summary>
        [Display(Name = "Associated Healthcare Provider (Optional)")]
        public Guid? ProviderId { get; set; }

        // --- UI Population Properties ---
        // These properties are not saved but are used to populate dropdowns and checkbox lists in the view.
        public SelectList? AvailableClientTypes { get; set; }
        public SelectList? AvailableApplicationTypes { get; set; }
        public SelectList? AvailableConsentTypes { get; set; }
        public List<SelectListItem> AllAvailablePermissions { get; set; } = new List<SelectListItem>();
        public List<SelectListItem> AllAvailableRequirements { get; set; } = new List<SelectListItem>();
        public SelectList? AvailableProviders { get; set; }


        // --- Helper Methods ---
        
        /// <summary>
        /// Converts the newline-separated `RedirectUris` string into an immutable array of <see cref="Uri"/> objects,
        /// safely parsing and ignoring any invalid entries.
        /// </summary>
        public ImmutableArray<Uri> GetRedirectUrisAsImmutableArray()
        {
            return RedirectUris?.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                .Select(uri => Uri.TryCreate(uri.Trim(), UriKind.Absolute, out var result) ? result : null)
                                .Where(uri => uri != null)
                                .Select(uri => uri!) // Non-null assertion is safe due to the preceding Where clause.
                                .ToImmutableArray() ?? ImmutableArray<Uri>.Empty;
        }

        /// <summary>
        /// Populates the `RedirectUris` string from an enumeration of URI strings.
        /// </summary>
        public void SetRedirectUrisFromStringList(IEnumerable<string>? uris)
        {
            RedirectUris = uris != null ? string.Join(Environment.NewLine, uris) : null;
        }

        /// <summary>
        /// Converts the newline-separated `PostLogoutRedirectUris` string into an immutable array of <see cref="Uri"/> objects.
        /// </summary>
        public ImmutableArray<Uri> GetPostLogoutRedirectUrisAsImmutableArray()
        {
            return PostLogoutRedirectUris?.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                          .Select(uri => Uri.TryCreate(uri.Trim(), UriKind.Absolute, out var result) ? result : null)
                                          .Where(uri => uri != null)
                                          .Select(uri => uri!)
                                          .ToImmutableArray() ?? ImmutableArray<Uri>.Empty;
        }

        /// <summary>
        /// Populates the `PostLogoutRedirectUris` string from an enumeration of URI strings.
        /// </summary>
        public void SetPostLogoutRedirectUrisFromStringList(IEnumerable<string>? uris)
        {
            PostLogoutRedirectUris = uris != null ? string.Join(Environment.NewLine, uris) : null;
        }
    }
}