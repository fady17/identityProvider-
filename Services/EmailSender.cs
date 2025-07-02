// Filename: EmailSender.cs
// Namespace: PlatformServices.Api.Services

using Microsoft.Extensions.Options; // For IOptions
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging; // For ILogger

namespace Orjnz.IdentityProvider.Web.Services
{
    // Configuration class for SMTP settings
    public class SmtpSettings
    {
        public string Server { get; set; } = string.Empty;
        public int Port { get; set; } = 587; // Default for Gmail with TLS
        public string Username { get; set; } = string.Empty; // Your Gmail address
        public string Password { get; set; } = string.Empty; // Your Gmail app password or account password (less secure)
        public bool UseSsl { get; set; } = true; // Gmail requires SSL/TLS
        public string SenderName { get; set; } = "Platform Services"; // Display name for the sender
        public string SenderEmail { get; set; } = string.Empty; // Usually same as Username
    }

    public class EmailSender : IEmailSender
    {
        private readonly SmtpSettings _smtpSettings;
        private readonly ILogger<EmailSender> _logger;

        public EmailSender(IOptions<SmtpSettings> smtpSettings, ILogger<EmailSender> logger)
        {
            _smtpSettings = smtpSettings.Value ?? throw new ArgumentNullException(nameof(smtpSettings));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            if (string.IsNullOrEmpty(_smtpSettings.Server) ||
                string.IsNullOrEmpty(_smtpSettings.Username) ||
                string.IsNullOrEmpty(_smtpSettings.Password) ||
                string.IsNullOrEmpty(_smtpSettings.SenderEmail))
            {
                _logger.LogError("SMTP settings are not fully configured. Email sending will likely fail.");
                // Depending on strictness, you might throw an exception here if settings are vital
                // throw new InvalidOperationException("SMTP settings are incomplete.");
            }
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            if (string.IsNullOrEmpty(_smtpSettings.Server) || string.IsNullOrEmpty(_smtpSettings.Username) || string.IsNullOrEmpty(_smtpSettings.Password))
            {
                _logger.LogError("SMTP settings are not configured. Cannot send email to {Email} with subject '{Subject}'.", email, subject);
                // add a fallback or a way to notify admins
                // For now, we just log and don't send if not configured.
                return; // Or throw an exception
            }

            try
            {
                var mailMessage = new MailMessage
                {
                    From = new MailAddress(_smtpSettings.SenderEmail, _smtpSettings.SenderName),
                    Subject = subject,
                    Body = htmlMessage,
                    IsBodyHtml = true,
                };
                mailMessage.To.Add(email);

                using (var smtpClient = new SmtpClient(_smtpSettings.Server, _smtpSettings.Port))
                {
                    smtpClient.Credentials = new NetworkCredential(_smtpSettings.Username, _smtpSettings.Password);
                    smtpClient.EnableSsl = _smtpSettings.UseSsl;
                    // smtpClient.DeliveryMethod = SmtpDeliveryMethod.Network; // Default

                    _logger.LogInformation("Attempting to send email to {Email} with subject '{Subject}' via SMTP server {SmtpServer}", email, subject, _smtpSettings.Server);
                    await smtpClient.SendMailAsync(mailMessage);
                    _logger.LogInformation("Email successfully sent to {Email} with subject '{Subject}'.", email, subject);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email to {Email} with subject '{Subject}'. SMTP Server: {SmtpServer}, Port: {Port}, SSL: {UseSsl}",
                    email, subject, _smtpSettings.Server, _smtpSettings.Port, _smtpSettings.UseSsl);
                // Do not re-throw typically for email sending unless it's critical path failure
                // The calling code should handle the fact that email might not have been sent.
            }
        }

        public async Task SendEmailConfirmationAsync(string email, string userName, string code)
        {
            var subject = "Confirm Your Email - Platform Services";
            var htmlMessage = CreateEmailConfirmationTemplate(userName, code);
            
            _logger.LogInformation("Sending email confirmation code to {Email} for user {UserName}", email, userName);
            await SendEmailAsync(email, subject, htmlMessage);
        }

        public async Task SendWelcomeEmailAsync(string email, string userName)
        {
            var subject = "Welcome to Platform Services!";
            var htmlMessage = CreateWelcomeEmailTemplate(userName);
            
            _logger.LogInformation("Sending welcome email to {Email} for user {UserName}", email, userName);
            await SendEmailAsync(email, subject, htmlMessage);
        }

        private string CreateEmailConfirmationTemplate(string userName, string code)
        {
            return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Email Confirmation</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f4f4f4;
        }}
        .container {{
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            color: #2c3e50;
            margin-bottom: 30px;
        }}
        .code-container {{
            background-color: #f8f9fa;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            margin: 30px 0;
        }}
        .verification-code {{
            font-size: 32px;
            font-weight: bold;
            color: #007bff;
            letter-spacing: 8px;
            margin: 10px 0;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            font-size: 12px;
            color: #666;
            text-align: center;
        }}
        .warning {{
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>🔐 Email Confirmation</h1>
            <p>Hello {userName}!</p>
        </div>
        
        <p>Thank you for registering with Platform Services. To complete your registration, please use the verification code below:</p>
        
        <div class='code-container'>
            <p><strong>Your Verification Code:</strong></p>
            <div class='verification-code'>{code}</div>
            <p><small>Enter this code on the confirmation page</small></p>
        </div>
        
        <div class='warning'>
            <strong>⚠️ Important:</strong>
            <ul style='margin: 10px 0; padding-left: 20px;'>
                <li>This code expires in 15 minutes</li>
                <li>Do not share this code with anyone</li>
                <li>If you didn't request this code, please ignore this email</li>
            </ul>
        </div>
        
        <p>If you're having trouble with the verification process, please contact our support team.</p>
        
        <div class='footer'>
            <p>This email was sent by Platform Services<br>
            If you did not create an account, please ignore this email.</p>
        </div>
    </div>
</body>
</html>";
        }

        private string CreateWelcomeEmailTemplate(string userName)
        {
            return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Welcome to Platform Services</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f4f4f4;
        }}
        .container {{
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            color: #2c3e50;
            margin-bottom: 30px;
        }}
        .welcome-banner {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            margin: 20px 0;
        }}
        .feature-list {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            font-size: 12px;
            color: #666;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>🎉 Welcome to Platform Services!</h1>
        </div>
        
        <div class='welcome-banner'>
            <h2>Hello {userName}!</h2>
            <p>Your email has been successfully confirmed and your account is now active.</p>
        </div>
        
        <p>We're excited to have you join our community! Here's what you can do now:</p>
        
        <div class='feature-list'>
            <h3>🚀 Get Started:</h3>
            <ul>
                <li>Complete your profile setup</li>
                <li>Explore our platform features</li>
                <li>Connect with other users</li>
                <li>Access premium services</li>
            </ul>
        </div>
        
        <p>If you have any questions or need assistance, our support team is here to help. Don't hesitate to reach out!</p>
        
        <p style='text-align: center; margin: 30px 0;'>
            <strong>Thank you for choosing Platform Services!</strong>
        </p>
        
        <div class='footer'>
            <p>Best regards,<br>
            The Platform Services Team</p>
        </div>
    </div>
</body>
</html>";
        }
    }
}