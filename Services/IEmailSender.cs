// Filename: IEmailSender.cs
// Namespace: PlatformServices.Api.Services

using System.Threading.Tasks;

namespace Orjnz.IdentityProvider.Web.Services
{
    /// <summary>
    /// Service interface for sending emails.
    /// </summary>
    public interface IEmailSender
    {
        /// <summary>
        /// Sends an email with custom subject and HTML content.
        /// </summary>
        /// <param name="email">The recipient's email address.</param>
        /// <param name="subject">The subject of the email.</param>
        /// <param name="htmlMessage">The HTML content of the email message.</param>
        Task SendEmailAsync(string email, string subject, string htmlMessage);
        
        /// <summary>
        /// Sends an email confirmation code to the user.
        /// </summary>
        /// <param name="email">The recipient's email address.</param>
        /// <param name="userName">The user's name for personalization.</param>
        /// <param name="code">The 6-digit confirmation code.</param>
        Task SendEmailConfirmationAsync(string email, string userName, string code);
        
        /// <summary>
        /// Sends a welcome email after successful email confirmation.
        /// </summary>
        /// <param name="email">The recipient's email address.</param>
        /// <param name="userName">The user's name for personalization.</param>
        Task SendWelcomeEmailAsync(string email, string userName);
    }
}