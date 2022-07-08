use rusoto_credential::{ChainProvider, ProvideAwsCredentials, AwsCredentials, CredentialsError};
use rusoto_core::{region::Region, HttpClient, request::TlsError, RusotoError};
use rusoto_s3::{GetObjectRequest, PutObjectRequest, util::{PreSignedRequestOption, PreSignedRequest}, S3, S3Client, CreateMultipartUploadRequest, StreamingBody, HeadObjectRequest};
use thiserror::Error;
use rocket::tokio::io::AsyncReadExt;

const BUCKET: &str = "bucket";

#[derive(Error, Debug)]
pub enum S3Error {
    #[error("Error while creating the http client: {0}")]
    Client(#[from] TlsError),
    #[error("Error while generating S3 credentials: {0}")]
    Credentials(#[from] CredentialsError),
    #[error("Download of S3 file failed: {0}")]
    DownloadError(String),
    #[error("S3 contribution file is present but empty")]
    EmptyContribution,
    #[error("S3 contribution file signature is present but empty")]
    EmptyContributionSignature,
    #[error("Error in IO: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Upload of challenge to S3 failed: {0}")]
    UploadError(String)
}

type Result<T> = std::result::Result<T, S3Error>;

pub(crate) struct S3Ctx { //FIXME: place this inside coordinator? But I would neeed a lock at that point. It depends on how fast it is the get_s3_ctx function
    client: S3Client,
    region: Region,
    options: PreSignedRequestOption,
    credentials: AwsCredentials
}

pub(crate) async fn get_s3_ctx() -> Result<S3Ctx> {
    let start = std::time::Instant::now(); //FIXME: remove
    let provider = ChainProvider::new();
    let endpoint = std::env::var("AWS_S3_ENDPOINT").unwrap_or("http://localhost:4566".to_string());
    let region = Region::Custom {
        name: "custom".to_string(),
        endpoint
    };
    let credentials = provider.credentials().await?;
    let client = S3Client::new_with(HttpClient::new()?, provider, region.clone());
    let options = PreSignedRequestOption {
        expires_in: std::time::Duration::from_secs(300),
    };
    
    tracing::info!("Created S3 context in {:?}", start.elapsed()); //FIXME: remove
    Ok(S3Ctx {
        client,
        region,
        options,
        credentials
    })
}

/// Get the url of a challenge on S3.
pub(crate) async fn get_challenge_url(ctx: &S3Ctx, key: String) -> Option<String> {
    let head = HeadObjectRequest {
        bucket: BUCKET.to_string(),
        key: key.clone(),
        ..Default::default()
    };

    if ctx.client.head_object(head).await.is_ok() {
        let get = GetObjectRequest {
            bucket: BUCKET.to_string(),
            key,
            ..Default::default()
        };

        Some(get.get_presigned_url(&ctx.region, &ctx.credentials, &ctx.options))
    } else {
        None
    }
}

/// Upload a challenge to S3.
pub(crate) async fn upload_challenge(ctx: &S3Ctx, key: String, challenge: Vec<u8>) -> Result<String> {
    let put_object_request = PutObjectRequest {
        bucket: BUCKET.to_string(),
        key: key.clone(),
        body: Some(StreamingBody::from(challenge)),
        ..Default::default()
    };
    
    let upload_result = ctx.client.put_object(put_object_request).await.map_err(|e| S3Error::UploadError(e.to_string()))?;

    let get = GetObjectRequest {
        bucket: BUCKET.to_string(),
        key,
        ..Default::default()
    };

    Ok(get.get_presigned_url(&ctx.region, &ctx.credentials, &ctx.options))
}

/// Get the urls of a contribution and its signature.
pub(crate) fn get_contribution_urls(ctx: &S3Ctx, contrib_key: String, contrib_sig_key: String) -> (String, String) {
    let get_contrib = GetObjectRequest {
        bucket: BUCKET.to_string(),
        key: contrib_key,
        ..Default::default()
    };
    let get_sig = GetObjectRequest {
        bucket: BUCKET.to_string(),
        key: contrib_sig_key,
        ..Default::default()
    };

    // NOTE: urls live for 5 minutes so we cannot cache them for reuse because there's a high chance they expired, we
    //  need to regenerate them every time
    let contrib_url = get_contrib.get_presigned_url(&ctx.region, &ctx.credentials, &ctx.options);
    let contrib_sig_url = get_sig.get_presigned_url(&ctx.region, &ctx.credentials, &ctx.options);

    (contrib_url, contrib_sig_url)
}

/// Download an object from S3 as bytes
async fn get_object(ctx: &S3Ctx, get_request: GetObjectRequest) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let stream = ctx.client.get_object(get_request).await.map_err(|e| S3Error::DownloadError(e.to_string()))?.body.ok_or(S3Error::EmptyContribution)?;
    stream.into_async_read().read_to_end(&mut buffer).await?;

    Ok(buffer)
}

/// Retrieve a contribution and its signature from S3.
pub(crate) async fn get_contribution(ctx: &S3Ctx, round_height: u64) -> Result<(Vec<u8>, Vec<u8>)> {
    let get_contrib = GetObjectRequest {
        bucket: BUCKET.to_string(),
        key: format!("round_{}/chunk_0/contribution_1.unverified", round_height),
        ..Default::default()
    };
    let get_sig = GetObjectRequest {
        bucket: BUCKET.to_string(),
        key: format!("round_{}/chunk_0/contribution_1.unverified.signature", round_height),
        ..Default::default()
    };

    rocket::tokio::try_join!(
        get_object(ctx, get_contrib),
        get_object(ctx, get_sig)
    )
}

// FIXME: review errors if it's better to unwrap