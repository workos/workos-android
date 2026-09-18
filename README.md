# WorkOS Android SDK

The WorkOS Android SDK provides access to AuthKit from Kotlin applications. Use
`PublicClient` to sign users in with PKCE using only your application's client ID.

> **Never include a WorkOS API key or client secret in an Android app.** Anything
> shipped in an APK is extractable. API keys belong only in trusted server
> environments.

## Requirements

- Android 8.0 (API level 26) or later
- Kotlin 2.4 or later
- JDK 17

## Installation

Add Maven Central to your repositories, then add the SDK to your app module's
`build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.workos:workos-android:x.x.x")
}
```

## Quickstart

Create a [WorkOS account](https://dashboard.workos.com/), copy your application's
client ID, and register a redirect URI in the Dashboard. Use the same URI in your
app's callback intent filter and when starting sign-in.

```kotlin
import com.workos.android.helpers.PublicClient

val workos = PublicClient.create(clientId = "client_...")
val authorization = workos.getAuthorizationUrlWithPkce(
    redirectUri = "com.example.myapp://callback",
)
```

Securely persist `authorization.codeVerifier` and `authorization.state` before
opening `authorization.url` in a Custom Tab, not a WebView. Both values must
survive Android process death while the browser is open.

When the callback arrives, handle cancellation and errors, and reject a missing
or mismatched `state`. After validating it against the saved state, exchange the
authorization code using the saved verifier from a coroutine:

```kotlin
val authentication = workos.authenticateWithCode(
    code = authorizationCode,
    codeVerifier = savedCodeVerifier,
)
```

Clear the pending verifier and state after the exchange, including on failure.
Keep access tokens in memory and refresh tokens in Keystore-backed storage; never
log either token.

## Next steps

- [Android sign-in tutorial](https://workos.com/blog/sign-in-to-an-android-app-with-the-workos-android-sdk): callback handling, secure storage, token refresh, and sign-out.
- [AuthKit documentation](https://workos.com/docs/authkit)
- [Android SDK API reference](https://workos.github.io/workos-android/)
- [GitHub Releases](https://github.com/workos/workos-android/releases): review the release notes before upgrading.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and generated-code guidance.

## License

MIT
