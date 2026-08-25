namespace OAuthAuthentication;

/// <summary>Configuration needed to perform an OAuth 2.0 authorization-code flow with PKCE.</summary>
public sealed class OAuthOptions
{
    public required string ClientId { get; init; }

    public required Uri RedirectUri { get; init; }

    /// <summary>The space-separated scopes requested from the provider.</summary>
    public required string Scopes { get; init; }

    /// <summary>The OpenID Connect discovery document URL.</summary>
    public Uri? DiscoveryEndpoint { get; init; }

    /// <summary>An explicit authorization endpoint. Overrides the value from discovery.</summary>
    public Uri? AuthorizationEndpoint { get; init; }

    /// <summary>An explicit token endpoint. Overrides the value from discovery.</summary>
    public Uri? TokenEndpoint { get; init; }

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(ClientId))
            throw new ArgumentException("A client ID is required.", nameof(ClientId));
        if (RedirectUri is null || !RedirectUri.IsAbsoluteUri)
            throw new ArgumentException("The redirect URI must be absolute.", nameof(RedirectUri));
        if (string.IsNullOrWhiteSpace(Scopes))
            throw new ArgumentException("At least one scope is required.", nameof(Scopes));
        if (DiscoveryEndpoint is null && (AuthorizationEndpoint is null || TokenEndpoint is null))
            throw new ArgumentException(
                "Configure a discovery endpoint or both authorization and token endpoints.");
        ValidateAbsolute(DiscoveryEndpoint, nameof(DiscoveryEndpoint));
        ValidateAbsolute(AuthorizationEndpoint, nameof(AuthorizationEndpoint));
        ValidateAbsolute(TokenEndpoint, nameof(TokenEndpoint));
    }

    private static void ValidateAbsolute(Uri? uri, string name)
    {
        if (uri is not null && !uri.IsAbsoluteUri)
            throw new ArgumentException($"The {name} URI must be absolute.", name);
    }
}
