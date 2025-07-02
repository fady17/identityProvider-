
using Microsoft.AspNetCore.Identity;

namespace Orjnz.IdentityProvider.Web.Data
{
    public class ApplicationRole : IdentityRole<string> // Using string as the key type, matching IdentityUser's default
    {
        public string? Description { get; set; }

      
        public ApplicationRole() : base() { }
        public ApplicationRole(string roleName) : base(roleName) { }
        public ApplicationRole(string roleName, string? description) : base(roleName)
        {
            Description = description;
        }
    }
}