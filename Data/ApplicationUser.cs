// File: ApplicationUser.cs - Fixed version
using Microsoft.AspNetCore.Identity;

namespace Orjnz.IdentityProvider.Web.Data
{
    // Add profile data for application users by adding properties to the ApplicationUser class
    public class ApplicationUser : IdentityUser<string>  // Inherit from IdentityUser
    {
        [PersonalData] // Annotate personal data for GDPR compliance / Identity UI management
        public string? FirstName { get; set; }

        [PersonalData]
        public string? LastName { get; set; }

        // This will store the unique ID of the healthcare provider this user might be primarily associated with.
        // It's nullable because not all users (e.g., general platform users, IDP admins)
        // might be directly tied to a single healthcare provider in this way.
        public Guid? DefaultProviderId { get; set; }
    }
}
