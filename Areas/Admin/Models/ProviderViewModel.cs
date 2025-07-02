// File: Orjnz.IdentityProvider.Web/Areas/Admin/Models/ProviderViewModel.cs
using System;
using System.ComponentModel.DataAnnotations;

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Models
{
    public class ProviderViewModel
    {
        public Guid Id { get; set; } // Hidden for Edit, not shown for Create

        [Required(ErrorMessage = "Provider name is required")]
        [StringLength(200, MinimumLength = 3, ErrorMessage = "Provider name must be between 3 and 200 characters")]
        [Display(Name = "Provider Name")]
        public string Name { get; set; } = string.Empty;

        [Required(ErrorMessage = "Short code is required")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "Short code must be between 3 and 50 characters")]
        [RegularExpression(@"^[a-zA-Z0-9\-]+$", ErrorMessage = "Short code can only contain letters, numbers, and hyphens")]
        [Display(Name = "Short Code")]
        public string ShortCode { get; set; } = string.Empty;

        [StringLength(256, ErrorMessage = "Website domain cannot exceed 256 characters")]
        [Display(Name = "Website Domain")]
        [RegularExpression(@"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$", 
            ErrorMessage = "Please enter a valid domain name (e.g., example.com)")]
        public string? WebsiteDomain { get; set; }

        [Display(Name = "Active")]
        public bool IsActive { get; set; } = true;
    }
}