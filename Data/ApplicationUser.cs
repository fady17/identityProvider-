using Microsoft.AspNetCore.Identity;

namespace Orjnz.IdentityProvider.Web.Data
{
    /// <summary>
    /// Represents a user in the application, extending the default ASP.NET Core IdentityUser.
    /// This class allows for adding custom profile data for application users.
    /// </summary>
    /// <remarks>
    /// The key for the user is of type <see cref="string"/>.
    /// </remarks>
    public class ApplicationUser : IdentityUser<string>
    {
        /// <summary>
        /// The user's first name.
        /// </summary>
        /// <remarks>
        /// Annotated with [PersonalData] to be recognized by the Identity system for GDPR data management.
        /// </remarks>
        [PersonalData]
        public string? FirstName { get; set; }

        /// <summary>
        /// The user's last name.
        /// </summary>
        /// <remarks>
        /// Annotated with [PersonalData] to be recognized by the Identity system for GDPR data management.
        /// </remarks>
        [PersonalData]
        public string? LastName { get; set; }

        /// <summary>
        /// Gets or sets the unique identifier of the default healthcare provider this user is associated with.
        /// This property links a user to a specific tenant or organization within the system.
        /// </summary>
        /// <remarks>
        /// This is nullable because not all users (e.g., system administrators) may be directly tied to a provider.
        /// </remarks>
        public Guid? DefaultProviderId { get; set; }
    }
}