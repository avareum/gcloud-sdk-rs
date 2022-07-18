# gcloud-sdk for Rust

[![Latest Version](https://img.shields.io/crates/v/gcloud-sdk.svg)](https://crates.io/crates/gcloud-sdk)

This library generated from [Google API](https://github.com/googleapis/googleapis) using [tonic-build](https://github.com/hyperium/tonic/tree/master/tonic-build).

This is NOT OFFICAL gcloud sdk from Google (and it doesn't exist for Rust at the moment of this page was updated).

## Overview
This library contains all the code generated from the Google API.

When using each product API, you must explicitly include it in your build using a feature flag.
For example, if you want to use [Cloud Pub/Sub](https://cloud.google.com/pubsub), write `features = ["google-pubsub-v1"]` to Cargo.toml.

The feature name is the period of the package name of each proto file, replaced by a hyphen.
If you specify a package, it will automatically load the dependent packages and include them in the build.
It means that `features = ["google-spanner-admin-database-v1"]`.

In addition, multiple features can be specified.

The list of available features can be found [here](./gcloud-sdk/Cargo.toml#L22-L390).

## Example

```rust
fn test() {
    // The library handles getting token from environment automatically
    let firestore_client: GoogleApi<FirestoreClient<GoogleAuthMiddleware>> =
        GoogleApi::from_function(
            FirestoreClient::new,
            "https://firestore.googleapis.com",
            // cloud resource prefix: used only for some of the APIs (such as Firestore)
            Some(cloud_resource_prefix.clone()),
        )
            .await?;

    let response = firestore_client
        .get()
        .list_documents(tonic::Request::new(ListDocumentsRequest {
            parent: format!("{}/documents", cloud_resource_prefix),
            ..Default::default()
        }))
        .await?;
}
```

Cargo.toml:
```toml
[dependencies]
gcloud-sdk = { version = "0.14", features = ["google-spanner-admin-database-v1"] }
tonic = { version = "0.7", features = ["tls"] }
prost = "0.10"
prost-types = "0.10"
tokio = { version = "1.14", features = ["rt-multi-thread", "time", "fs", "macros"] }
chrono = "0.4"
```

## Google authentication

Default Scope is `https://www.googleapis.com/auth/cloud-platform`.

To specify custom scopes there is `from_function_with_scopes()` function
instead of `from_function()`;

Looks for credentials in the following places, preferring the first location found:
- A JSON file whose path is specified by the GOOGLE_APPLICATION_CREDENTIALS environment variable.
- A JSON file in a location known to the gcloud command-line tool.
- On Google Compute Engine, it fetches credentials from the metadata server.

## Fork
The library is a fork of [mechiru/googapis](https://github.com/mechiru/googapis) and [mechiru/gouth](https://github.com/mechiru/gouth) to keep up with
the updates and API proto descriptions from Google more frequently and simplify dependencies management.

### Why not to contribute back?
- Different goals from googapis.
    * This fork focuses on simplicity and provided authentication capabilities natively.
    * Has direct dependencies to tokio runtime and chrono.
      Uses synchronisation primitives (such as Mutex) from tokio everywhere.
    * Provides facade API for the caching async client implementation based on Tower middleware
      that hides complexity working with tokens and TLS.
    * Improved observability with tracing and measuring execution time of endpoints.
- Different development cycles - the original development was updated less frequently than it was needed for me.

I'd be glad to contribute all of the changes back if author sees the same goals.

## High-level APIs
Sometimes using proto generated API is tedious and cumbersome, and there is a real

## License
Licensed under either of [Apache License, Version 2.0](./LICENSE-APACHE)
or [MIT license](./LICENSE-MIT) at your option.

## Authors
- [mechiru](https://github.com/mechiru) - the original project
- Abdulla Abdurakhmanov - updated for recent deps, introduced caching client implementation, merged/refactorings with gouth.
