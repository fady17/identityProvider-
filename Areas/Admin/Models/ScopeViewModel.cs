// File: Orjnz.IdentityProvider.Web/Areas/Admin/Models/ScopeViewModel.cs
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Models
{
    public class ScopeViewModel
    {
        // For Edit/Details, not shown directly on Create form but used by handler
        public string? Id { get; set; } // OpenIddict scope ID (string)

        [Required(ErrorMessage = "Scope name is required.")]
        [StringLength(200, MinimumLength = 3, ErrorMessage = "Scope name must be between 3 and 200 characters.")]
        [RegularExpression(@"^[a-zA-Z0-9_.:-]+$", ErrorMessage = "Scope name can only contain letters, numbers, underscores, periods, colons, and hyphens.")]
        [Display(Name = "Scope Name (e.g., openid, profile, api:read)")]
        public string Name { get; set; } = string.Empty;

        [StringLength(200, ErrorMessage = "Display name cannot exceed 200 characters.")]
        [Display(Name = "Display Name (User-friendly name)")]
        public string? DisplayName { get; set; }

        [DataType(DataType.MultilineText)]
        [Display(Name = "Description (Optional)")]
        public string? Description { get; set; }

        [Display(Name = "Associated Resources (Audiences - one per line)")]
        [DataType(DataType.MultilineText)]
        public string? Resources { get; set; } // Will be split/joined by newline

        // If you add custom properties to AppCustomOpenIddictScope, add them here too.
        // Example:
        // [Display(Name = "Requires Elevated Consent?")]
        // public bool RequiresElevatedConsent { get; set; }
    }
}