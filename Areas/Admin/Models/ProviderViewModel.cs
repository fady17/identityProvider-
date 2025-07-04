using System;
using System.ComponentModel.DataAnnotations;

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Models
{
    /// <summary>
    /// Represents the view model for creating and editing a Provider.
    /// This model facilitates data transfer between the admin UI forms and the backend logic,
    /// and includes data annotations for validation and display purposes.
    /// </summary>
    public class ProviderViewModel
    {
        /// <summary>
        /// The unique database identifier of the Provider.
        /// This is used to track the entity for updates but is not typically displayed on a creation form.
        /// </summary>
        public Guid Id { get; set; }

        /// <summary>
        /// The full, user-friendly name of the healthcare provider or organization.
        /// </summary>
        [Required(ErrorMessage = "Provider name is required")]
        [StringLength(200, MinimumLength = 3, ErrorMessage = "Provider name must be between 3 and 200 characters")]
        [Display(Name = "Provider Name")]
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// A short, unique code used to identify the provider programmatically.
        /// This is often used to construct unique identifiers, such as API audiences (e.g., "{ShortCode}-api").
        /// </summary>
        [Required(ErrorMessage = "Short code is required")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "Short code must be between 3 and 50 characters")]
        [RegularExpression(@"^[a-zA-Z0-9\-]+$", ErrorMessage = "Short code can only contain letters, numbers, and hyphens")]
        [Display(Name = "Short Code")]
        public string ShortCode { get; set; } = string.Empty;

        /// <summary>
        /// The optional primary website domain associated with the provider.
        /// </summary>
        [StringLength(256, ErrorMessage = "Website domain cannot exceed 256 characters")]
        [Display(Name = "Website Domain")]
        [RegularExpression(@"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$", 
            ErrorMessage = "Please enter a valid domain name (e.g., example.com)")]
        public string? WebsiteDomain { get; set; }

        /// <summary>
        /// A flag to indicate whether the provider is active and available for use in the system.
        /// Defaults to `true` for new providers.
        /// </summary>
        [Display(Name = "Active")]
        public bool IsActive { get; set; } = true;
    }
}