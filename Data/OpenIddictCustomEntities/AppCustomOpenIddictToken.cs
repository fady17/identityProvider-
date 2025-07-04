using OpenIddict.EntityFrameworkCore.Models;

namespace Orjnz.IdentityProvider.Web.Data.OpenIddictCustomEntities
{
    /// <summary>
    /// Represents a custom OpenIddict token entity.
    /// This class inherits from the base OpenIddict type and is defined to maintain type consistency
    /// across the custom entity model, allowing for future extensions if needed.
    /// </summary>
    public class AppCustomOpenIddictToken : OpenIddictEntityFrameworkCoreToken<string, AppCustomOpenIddictApplication, AppCustomOpenIddictAuthorization>
    {
        // No custom properties are added at this time, but this class provides an extension point for the future.
        // For example, one could add a property to store session identifiers or other metadata related to the token.
    }
}