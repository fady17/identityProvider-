using Microsoft.AspNetCore.Identity;

namespace Orjnz.IdentityProvider.Web.Data
{
    /// <summary>
    /// Represents a role in the application, extending the default ASP.NET Core IdentityRole.
    /// Allows for adding custom properties to roles, such as a description.
    /// </summary>
    /// <remarks>
    /// The key for the role is of type <see cref="string"/>, matching the user's key type.
    /// </remarks>
    public class ApplicationRole : IdentityRole<string>
    {
        /// <summary>
        /// A description of the role's purpose and permissions.
        /// </summary>
        public string? Description { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ApplicationRole"/> class.
        /// </summary>
        public ApplicationRole() : base() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="ApplicationRole"/> class with the specified role name.
        /// </summary>
        /// <param name="roleName">The name of the role.</param>
        public ApplicationRole(string roleName) : base(roleName) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="ApplicationRole"/> class with the specified role name and description.
        /// </summary>
        /// <param name="roleName">The name of the role.</param>
        /// <param name="description">The description of the role.</param>
        public ApplicationRole(string roleName, string? description) : base(roleName)
        {
            Description = description;
        }
    }
}