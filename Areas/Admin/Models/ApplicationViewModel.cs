// File: Orjnz.IdentityProvider.Web/Areas/Admin/Models/ApplicationViewModel.cs
using Microsoft.AspNetCore.Mvc.Rendering; // For SelectList
using OpenIddict.Abstractions; // For OpenIddictConstants
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using static OpenIddict.Abstractions.OpenIddictConstants; // For easy access to constants

namespace Orjnz.IdentityProvider.Web.Areas.Admin.Models
{
    public class ApplicationViewModel
    {
        // For Edit/Details, not shown directly on Create form but used by handler
        public string? Id { get; set; } // OpenIddict application ID (string)

        [Required(ErrorMessage = "Client ID is required.")]
        [StringLength(100, MinimumLength = 3, ErrorMessage = "Client ID must be between 3 and 100 characters.")]
        [RegularExpression(@"^[a-zA-Z0-9_.\-]+$", ErrorMessage = "Client ID can only contain letters, numbers, underscores, hyphens, and periods.")]
        [Display(Name = "Client ID (Unique Identifier)")]
        public string ClientId { get; set; } = string.Empty;

        [Display(Name = "Client Secret (for Confidential Clients)")]
        [StringLength(200, ErrorMessage = "Client secret cannot exceed 200 characters.")]
        // No MinimumLength here, as it might be auto-generated or intentionally short for some test cases.
        // It's only relevant if ClientType is Confidential.
        public string? ClientSecret { get; set; }

        [Required(ErrorMessage = "Display name is required.")]
        [StringLength(150, MinimumLength = 3, ErrorMessage = "Display name must be between 3 and 150 characters.")]
        [Display(Name = "Display Name")]
        public string DisplayName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Client type is required.")]
        [Display(Name = "Client Type")]
        public string ClientType { get; set; } = ClientTypes.Public; // Default to Public

        [Display(Name = "Application Type (Optional)")]
        public string? ApplicationType { get; set; } // e.g., Web, Native

        [Display(Name = "Consent Type (Optional)")]
        public string? ConsentType { get; set; } // e.g., Explicit, Implicit, External, Systematic

        [Display(Name = "Redirect URIs (one per line)")]
        [DataType(DataType.MultilineText)]
        public string? RedirectUris { get; set; } // Will be split by newline

        [Display(Name = "Post-Logout Redirect URIs (one per line)")]
        [DataType(DataType.MultilineText)]
        public string? PostLogoutRedirectUris { get; set; } // Will be split by newline

        // Permissions are complex. We'll use a list of strings for selection.
        // The view will need to present these as checkboxes or a multi-select.
        [Display(Name = "Permissions")]
        public List<string> SelectedPermissions { get; set; } = new List<string>();

        [Display(Name = "Requirements")]
        public List<string> SelectedRequirements { get; set; } = new List<string>();


        // For linking to our custom Provider entity
        [Display(Name = "Associated Healthcare Provider (Optional)")]
        public Guid? ProviderId { get; set; }

        // --- Data for Populating UI Controls (not directly part of the model to be saved) ---
        public SelectList? AvailableClientTypes { get; set; }
        public SelectList? AvailableApplicationTypes { get; set; }
        public SelectList? AvailableConsentTypes { get; set; }
        public List<SelectListItem> AllAvailablePermissions { get; set; } = new List<SelectListItem>();
        public List<SelectListItem> AllAvailableRequirements { get; set; } = new List<SelectListItem>();
        public SelectList? AvailableProviders { get; set; }


        // Helper methods to convert multi-line string URIs to/from collections
        public ImmutableArray<Uri> GetRedirectUrisAsImmutableArray()
        {
            return RedirectUris?.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                .Select(uri => Uri.TryCreate(uri.Trim(), UriKind.Absolute, out var result) ? result : null)
                                .Where(uri => uri != null)
                                .Select(uri => uri!) // Non-null assertion after Where
                                .ToImmutableArray() ?? ImmutableArray<Uri>.Empty;
        }

        public void SetRedirectUrisFromStringList(IEnumerable<string>? uris)
        {
            RedirectUris = uris != null ? string.Join(Environment.NewLine, uris) : null;
        }

        public ImmutableArray<Uri> GetPostLogoutRedirectUrisAsImmutableArray()
        {
            return PostLogoutRedirectUris?.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                          .Select(uri => Uri.TryCreate(uri.Trim(), UriKind.Absolute, out var result) ? result : null)
                                          .Where(uri => uri != null)
                                          .Select(uri => uri!) // Non-null assertion
                                          .ToImmutableArray() ?? ImmutableArray<Uri>.Empty;
        }

        public void SetPostLogoutRedirectUrisFromStringList(IEnumerable<string>? uris)
        {
            PostLogoutRedirectUris = uris != null ? string.Join(Environment.NewLine, uris) : null;
        }
    }
}