using System.Security.Cryptography;

namespace OAuthAuthentication.Utilities;

public static class CodeVerifier
{
    /// <summary>Creates a cryptographically secure PKCE verifier.</summary>
    public static string GenerateCodeVerifier()
    {
        var bytes = new byte[32];

        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);

        return Convert.ToBase64String(bytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .TrimEnd('=');
    }
}
