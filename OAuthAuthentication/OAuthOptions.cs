namespace OAuthAuthentication;

/// <summary>Configuration needed to perform an OAuth 2.0 authorization-code flow.</summary>
public sealed class OAuthOptions
{
    /// <summary>The client ID supplied by the OAuth provider.</summary>
    public required string ClientId { get; init; }

    /// <summary>The client secret supplied by the OAuth provider.</summary>
    public required string ClientSecret { get; init; }

    public required Uri RedirectUri { get; init; }

    /// <summary>The space-separated scopes requested from the provider.</summary>
    public required string Scopes { get; init; }

    /// <summary>Whether to protect the authorization-code flow with PKCE.</summary>
    public bool UsePkce { get; init; } = true;

    /// <summary>The OpenID Connect discovery document URL.</summary>
    public Uri? DiscoveryEndpoint { get; init; }

    /// <summary>An explicit authorization endpoint. Overrides the value from discovery.</summary>
    public Uri? AuthorizationEndpoint { get; init; }

    /// <summary>An explicit token endpoint. Overrides the value from discovery.</summary>
    public Uri? TokenEndpoint { get; init; }

    /// <summary>How the client credentials are sent to the token endpoint.</summary>
    public TokenEndpointAuthenticationMethod TokenEndpointAuthenticationMethod { get; init; } =
        TokenEndpointAuthenticationMethod.ClientSecretPost;

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(ClientId))
            throw new ArgumentException("A client ID is required.", nameof(ClientId));
        if (string.IsNullOrWhiteSpace(ClientSecret))
            throw new ArgumentException("A client secret is required.", nameof(ClientSecret));
        if (RedirectUri is null || !RedirectUri.IsAbsoluteUri)
            throw new ArgumentException("The redirect URI must be absolute.", nameof(RedirectUri));
        if (string.IsNullOrWhiteSpace(Scopes))
            throw new ArgumentException("At least one scope is required.", nameof(Scopes));
        if (DiscoveryEndpoint is null && (AuthorizationEndpoint is null || TokenEndpoint is null))
            throw new ArgumentException(
                "Configure a discovery endpoint or both authorization and token endpoints.");
        if (!Enum.IsDefined(TokenEndpointAuthenticationMethod))
            throw new ArgumentOutOfRangeException(
                nameof(TokenEndpointAuthenticationMethod),
                TokenEndpointAuthenticationMethod,
                "Select a supported token endpoint authentication method.");
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

/// <summary>Standard OAuth 2.0 client authentication methods for the token endpoint.</summary>
public enum TokenEndpointAuthenticationMethod
{
    /// <summary>Send client credentials as form fields in the token request.</summary>
    ClientSecretPost,

    /// <summary>Send client credentials using HTTP Basic authentication.</summary>
    ClientSecretBasic
}
