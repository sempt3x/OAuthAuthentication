# OAuthAuthentication

Reusable OAuth 2.0 authorization-code logic with optional PKCE and no UI or application-settings dependency.

```csharp
using OAuthAuthentication;

var options = new OAuthOptions
{
    // Obtain every value below from user input or the host application's secure settings store.
    ClientId = configuredClientId,
    ClientSecret = configuredClientSecret,
    AuthorizationEndpoint = new Uri(configuredAuthorizationUrl),
    TokenEndpoint = new Uri(configuredTokenUrl),
    RedirectUri = new Uri(configuredRedirectUri),
    Scopes = configuredScopes,
    UsePkce = configuredUsePkce
};

IAuthenticationService authentication = new AuthenticationService(options);
var authorizationUrl = await authentication.GetConnectionLinkAsync();
```

The application opens `authorizationUrl` in its own browser/WebView. After receiving the redirect:

```csharp
var tokens = await authentication.GetTokenFromAuthorizationCodeAsync(code);
var refreshed = await authentication.GetTokenFromRefreshTokenAsync(tokens.RefreshToken);
bool valid = AuthenticationService.IsTokenValid(refreshed.AccessToken);
```

`UsePkce` defaults to `true`. When enabled, the service generates a verifier, adds its S256 challenge
to the authorization URL, and sends the verifier during the authorization-code exchange. Keep the
same service instance between those two operations so it retains the generated verifier. Set
`UsePkce = false` for the standard authorization-code flow without PKCE; no verifier is generated and
no PKCE parameters are sent.

`OAuthOptions` contains no provider-specific credentials, endpoints, or scopes. A host UI should
collect the client ID, client secret, authorization URL, token URL, redirect URI, space-separated
scopes, and PKCE preference from the user. Provider presets may populate public endpoint URLs, but
must not supply client credentials or hardcode the PKCE setting.

The client secret is sent only to the token endpoint. `ClientSecretPost` is the default authentication
method. Providers requiring HTTP Basic authentication can be configured with:

```csharp
TokenEndpointAuthenticationMethod = TokenEndpointAuthenticationMethod.ClientSecretBasic
```

This library intentionally has no UI or application-settings dependency. Consumers own UI and
persistence, and should keep client secrets and returned tokens in an operating-system credential
vault or another encrypted secret store. Do not log or store them as plain text.
