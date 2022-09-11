use url::form_urlencoded::Serializer;

use async_trait::async_trait;
use hyper::http::uri::PathAndQuery;
use std::convert::TryFrom;
use std::str::FromStr;
use tracing::trace;

use crate::token_source::{BoxSource, Source, Token, TokenResponse};

#[derive(Debug)]
pub struct Metadata {
    account: &'static str,
    scopes: Vec<String>,
    gcemeta_client: gcemeta::Client<hyper::client::connect::HttpConnector, hyper::Body>,
}

impl Metadata {
    pub fn new(scopes: impl Into<Vec<String>>) -> Self {
        Self::with_account(scopes, "default")
    }

    pub fn with_account(scopes: impl Into<Vec<String>>, account: &'static str) -> Self {
        Self {
            account,
            scopes: scopes.into(),
            gcemeta_client: gcemeta::Client::new(),
        }
    }

    fn uri_suffix(&self) -> String {
        let query = if self.scopes.is_empty() {
            String::new()
        } else {
            Serializer::new(String::new())
                .append_pair("scopes", &self.scopes.join(","))
                .finish()
        };
        format!("instance/service-accounts/{}/token?{}", self.account, query)
    }

    fn uri_suffix_identity(&self) -> String {
        let query = if self.scopes.is_empty() {
            String::new()
        } else {
            Serializer::new(String::new())
                .append_pair("audience", &self.scopes.join(","))
                .finish()
        };
        format!(
            "instance/service-accounts/{}/identity?{}",
            self.account, query
        )
    }

    pub async fn detect_google_project_id(&self) -> Option<String> {
        self.gcemeta_client.project_id().await.ok()
    }
}

impl From<Metadata> for BoxSource {
    fn from(v: Metadata) -> Self {
        Box::new(v)
    }
}

#[async_trait]
impl Source for Metadata {
    async fn token(&self) -> crate::error::Result<Token> {
        let url =
            PathAndQuery::from_str(format!("/computeMetadata/v1/{}", self.uri_suffix()).as_str())?;
        trace!("Receiving a new token from Metadata Server using '{}'", url);

        let resp_str = self.gcemeta_client.get(url, false).await?;
        let resp = TokenResponse::try_from(resp_str.as_str())?;
        Token::try_from(resp)
    }

    async fn identity(&self) -> crate::error::Result<Token> {
        let url = PathAndQuery::from_str(
            format!("/computeMetadata/v1/{}", self.uri_suffix_identity()).as_str(),
        )?;
        trace!(
            "Receiving a new identity from Metadata Server using '{}'",
            url
        );

        let resp_str = self.gcemeta_client.get(url, false).await?;

        Token::try_from(resp_str)
    }
}

pub async fn from_metadata(scopes: &[String]) -> crate::error::Result<Option<Metadata>> {
    let gcemeta_client = gcemeta::Client::new();

    if gcemeta_client.on_gce().await? {
        Ok(Some(Metadata::new(scopes)))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_metadata_uri_suffix() {
        let m = Metadata::new(Vec::new());
        assert_eq!(m.uri_suffix(), "instance/service-accounts/default/token?");

        let m = Metadata::new(vec!["https://www.googleapis.com/auth/cloud-platform".into()]);

        assert_eq!(
            m.uri_suffix(),
            "instance/service-accounts/default/token?scopes=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform"
        );

        let m = Metadata::new(vec!["scope1".into(), "scope2".into()]);
        assert_eq!(
            m.uri_suffix(),
            "instance/service-accounts/default/token?scopes=scope1%2Cscope2",
        );
    }
}
