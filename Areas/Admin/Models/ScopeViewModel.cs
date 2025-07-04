using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Models
{
    /// <summary>
    /// Represents the view model for creating and editing an OpenIddict scope.
    /// This model is used by the admin UI forms to gather scope information and includes
    /// data annotations for validation and display formatting.
    /// </summary>
    public class ScopeViewModel
    {
        /// <summary>
        /// The unique database identifier of the OpenIddict scope.
        /// This is null when creating a new scope and populated when editing an existing one.
        /// </summary>
        public string? Id { get; set; }

        /// <summary>
        /// The programmatic name of the scope (e.g., "openid", "profile", "api:read").
        /// This is the identifier that client applications will request.
        /// </summary>
        [Required(ErrorMessage = "Scope name is required.")]
        [StringLength(200, MinimumLength = 3, ErrorMessage = "Scope name must be between 3 and 200 characters.")]
        [RegularExpression(@"^[a-zA-Z0-9_.:-]+$", ErrorMessage = "Scope name can only contain letters, numbers, underscores, periods, colons, and hyphens.")]
        [Display(Name = "Scope Name (e.g., openid, profile, api:read)")]
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// A user-friendly name for the scope, which can be displayed on the consent screen
        /// to provide a more understandable label for the permission being requested.
        /// </summary>
        [StringLength(200, ErrorMessage = "Display name cannot exceed 200 characters.")]
        [Display(Name = "Display Name (User-friendly name)")]
        public string? DisplayName { get; set; }

        /// <summary>
        /// A detailed description of what the scope allows. This can also be displayed on
        /// the consent screen to give the user more context before granting permission.
        /// </summary>
        [DataType(DataType.MultilineText)]
        [Display(Name = "Description (Optional)")]
        public string? Description { get; set; }

        /// <summary>
        /// A newline-separated list of resource identifiers (audiences) that this scope is associated with.
        /// When a client is granted this scope, the resulting access token will be valid for these audiences,
        /// allowing it to be used to call the corresponding resource APIs.
        /// </summary>
        [Display(Name = "Associated Resources (Audiences - one per line)")]
        [DataType(DataType.MultilineText)]
        public string? Resources { get; set; }

        // This is an extension point. If custom properties were added to the `AppCustomOpenIddictScope`
        // entity (e.g., a boolean to flag scopes that require special handling), a corresponding
        // property would be added here to be managed through the UI.
        // Example:
        // [Display(Name = "Requires Elevated Consent?")]
        // public bool RequiresElevatedConsent { get; set; }
    }
}