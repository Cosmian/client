use std::fmt::Display;

use cosmian_config::ClientConf;
use cosmian_http_client::HttpClient;
use der::{DecodePem, Encode};
use reqwest::{Response, StatusCode};
use rustls::Certificate;
use serde::{Deserialize, Serialize};
use tracing::{instrument, trace};
use uuid::Uuid;
use x509_cert::Certificate as X509Certificate;

use crate::{
    error::{
        result::{FindexRestClientResult, FindexRestClientResultHelper},
        FindexRestClientError,
    },
    Permission,
};

// Response for success
#[derive(Deserialize, Serialize, Debug)] // Debug is required by ok_json()
pub struct SuccessResponse {
    pub success: String,
}

impl Display for SuccessResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.success)
    }
}

#[derive(Clone)]
pub struct FindexRestClient {
    pub client: HttpClient,
}

impl FindexRestClient {
    /// Initialize a Findex REST client.
    ///
    /// Parameters `server_url` and `accept_invalid_certs` from the command line
    /// will override the ones from the configuration file.
    pub fn new(conf: ClientConf) -> Result<FindexRestClient, FindexRestClientError> {
        let findex_client_conf = conf.findex_client_conf.ok_or_else(|| {
            FindexRestClientError::Default("No Findex client configuration found".to_owned())
        })?;

        // Instantiate a Findex server REST client with the given configuration
        let kms_rest_client = HttpClient::instantiate(
            &findex_client_conf.server_url,
            findex_client_conf.access_token.as_deref(),
            findex_client_conf.ssl_client_pkcs12_path.as_deref(),
            findex_client_conf.ssl_client_pkcs12_password.as_deref(),
            findex_client_conf.kms_database_secret.as_deref(),
            findex_client_conf.accept_invalid_certs,
            if let Some(certificate) = &findex_client_conf.verified_cert {
                Some(Certificate(
                    X509Certificate::from_pem(certificate.as_bytes())?.to_der()?,
                ))
            } else {
                None
            },
        )
        .with_context(|| {
            format!(
                "Unable to instantiate a Findex REST client to server at {}",
                findex_client_conf.server_url
            )
        })?;

        Ok(FindexRestClient {
            client: kms_rest_client,
        })
    }

    #[instrument(ret(Display), err, skip(self))]
    pub async fn create_index_id(&self) -> FindexRestClientResult<SuccessResponse> {
        let endpoint = "/create/index".to_owned();
        let server_url = format!("{}{endpoint}", self.client.server_url);
        trace!("POST create_index_id: {server_url}");
        let response = self.client.client.post(server_url).send().await?;
        trace!("Response: {response:?}");
        let status_code = response.status();
        if status_code.is_success() {
            return Ok(response.json::<SuccessResponse>().await?);
        }

        // process error
        let p = handle_error(&endpoint, response).await?;
        Err(FindexRestClientError::RequestFailed(p))
    }

    #[instrument(ret(Display), err, skip(self))]
    pub async fn grant_permission(
        &self,
        user_id: &str,
        permission: &Permission,
        index_id: &Uuid,
    ) -> FindexRestClientResult<SuccessResponse> {
        let endpoint = format!("/permission/grant/{user_id}/{permission}/{index_id}");
        let server_url = format!("{}{endpoint}", self.client.server_url);
        trace!("POST grant_permission: {server_url}");
        let response = self.client.client.post(server_url).send().await?;
        let status_code = response.status();
        if status_code.is_success() {
            return Ok(response.json::<SuccessResponse>().await?);
        }

        // process error
        let p = handle_error(&endpoint, response).await?;
        Err(FindexRestClientError::RequestFailed(p))
    }

    #[instrument(ret(Display), err, skip(self))]
    pub async fn revoke_permission(
        &self,
        user_id: &str,
        index_id: &Uuid,
    ) -> FindexRestClientResult<SuccessResponse> {
        let endpoint = format!("/permission/revoke/{user_id}/{index_id}");
        let server_url = format!("{}{endpoint}", self.client.server_url);
        trace!("POST revoke_permission: {server_url}");
        let response = self.client.client.post(server_url).send().await?;
        let status_code = response.status();
        if status_code.is_success() {
            return Ok(response.json::<SuccessResponse>().await?);
        }

        // process error
        let p = handle_error(&endpoint, response).await?;
        Err(FindexRestClientError::RequestFailed(p))
    }

    #[instrument(ret(Display), err, skip(self))]
    pub async fn version(&self) -> FindexRestClientResult<String> {
        let endpoint = "/version";
        let server_url = format!("{}{endpoint}", self.client.server_url);
        let response = self.client.client.get(server_url).send().await?;
        let status_code = response.status();
        if status_code.is_success() {
            return Ok(response.json::<String>().await?);
        }

        // process error
        let p = handle_error(endpoint, response).await?;
        Err(FindexRestClientError::RequestFailed(p))
    }
}

/// Some errors are returned by the Middleware without going through our own error manager.
/// In that case, we make the error clearer here for the client.
async fn handle_error(endpoint: &str, response: Response) -> Result<String, FindexRestClientError> {
    trace!("Error response received on {endpoint}: Response: {response:?}");
    let status = response.status();
    let text = response.text().await?;

    Ok(format!(
        "{}: {}",
        endpoint,
        if text.is_empty() {
            match status {
                StatusCode::NOT_FOUND => "Findex server endpoint does not exist".to_owned(),
                StatusCode::UNAUTHORIZED => "Bad authorization token".to_owned(),
                _ => format!("{status} {text}"),
            }
        } else {
            text
        }
    ))
}
