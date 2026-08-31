# OAuthAuthentication

Reusable OAuth 2.0 authorization-code/PKCE logic with no UI or application-settings dependency.

```csharp
using OAuthAuthentication;
using OAuthAuthentication.Utilities;

var options = new OAuthOptions
{
    // Obtain every value below from user input or the host application's secure settings store.
    ClientId = configuredClientId,
    ClientSecret = configuredClientSecret,
    AuthorizationEndpoint = new Uri(configuredAuthorizationUrl),
    TokenEndpoint = new Uri(configuredTokenUrl),
    RedirectUri = new Uri(configuredRedirectUri),
    Scopes = configuredScopes
};

var verifier = CodeVerifier.GenerateCodeVerifier();
IAuthenticationService authentication = new AuthenticationService(options, verifier);
var authorizationUrl = await authentication.GetConnectionLinkAsync();
```

The application opens `authorizationUrl` in its own browser/WebView. After receiving the redirect:

```csharp
var tokens = await authentication.GetTokenFromAuthorizationCodeAsync(code);
var refreshed = await authentication.GetTokenFromRefreshTokenAsync(tokens.RefreshToken);
bool valid = AuthenticationService.IsTokenValid(refreshed.AccessToken);
```

Keep the same service instance (and therefore the same PKCE verifier) between URL generation and
the authorization-code exchange.

`OAuthOptions` contains no provider-specific credentials, endpoints, or scopes. A host UI should
collect the client ID, client secret, authorization URL, token URL, redirect URI, and space-separated
scopes from the user. Provider presets may populate public endpoint URLs, but must not supply client
credentials.

The client secret is sent only to the token endpoint. `ClientSecretPost` is the default authentication
method. Providers requiring HTTP Basic authentication can be configured with:

```csharp
TokenEndpointAuthenticationMethod = TokenEndpointAuthenticationMethod.ClientSecretBasic
```

This library intentionally has no UI or application-settings dependency. Consumers own UI and
persistence, and should keep client secrets and returned tokens in an operating-system credential
vault or another encrypted secret store. Do not log or store them as plain text.
