//! REST API endpoints exposed by the [Coordinator](`crate::Coordinator`).


// FIXME: split in two files

use crate::{
    authentication::{Production, Signature},
    objects::{ContributionInfo, LockedLocators, Task},
    s3::{S3Ctx, S3Error},
    storage::{ContributionLocator, ContributionSignatureLocator},
    CoordinatorError,
    Participant, CoordinatorState,
};

pub use crate::s3::TOKENS_ZIP_FILE;
pub use crate::coordinator_state::TOKENS_PATH;
use blake2::Digest;
use rocket::{
    catch,
    data::FromData,
    error,
    get,
    http::{ContentType, Status},
    post,
    request::{FromRequest, Outcome, Request},
    response::{Responder, Response},
    serde::{json::Json, Deserialize, DeserializeOwned, Serialize},
    tokio::{fs, sync::RwLock, task},
    Shutdown,
    State,
};

use sha2::Sha256;

use lazy_static::lazy_static;
use regex::Regex;
use std::{borrow::Cow, convert::TryFrom, io::{Cursor, Read, Write}, net::IpAddr, ops::Deref, sync::Arc, time::Duration, collections::{HashSet, HashMap}};
use thiserror::Error;

use tracing::warn;

#[cfg(debug_assertions)]
pub const UPDATE_TIME: Duration = Duration::from_secs(5);
#[cfg(not(debug_assertions))]
pub const UPDATE_TIME: Duration = Duration::from_secs(60);

pub const UNKNOWN: &str = "Unknown";
pub const TOKEN_REGEX: &str = r"^[[:xdigit:]]{20}$";

// Headers
pub const BODY_DIGEST_HEADER: &str = "Digest";
pub const PUBKEY_HEADER: &str = "ATS-Pubkey";
pub const SIGNATURE_HEADER: &str = "ATS-Signature";
pub const CONTENT_LENGTH_HEADER: &str = "Content-Length";
pub const ACCESS_SECRET_HEADER: &str = "Access-Secret";

lazy_static! {
    static ref HEALTH_PATH: String = match std::env::var("HEALTH_PATH") {
        Ok(path) => path,
        Err(_) => ".".to_string(),
    };

    static ref ACCESS_SECRET: String = std::env::var("ACCESS_SECRET").expect("Missing required env ACCESS_SECRET");
}

type Coordinator = Arc<RwLock<crate::Coordinator>>;

/// Server errors. Also includes errors generated by the managed [Coordinator](`crate::Coordinator`).
#[derive(Error, Debug)]
pub enum ResponseError {
    #[error("Ceremony is over, no more contributions are allowed")]
    CeremonyIsOver,
    #[error("Coordinator failed: {0}")]
    CoordinatorError(CoordinatorError),
    #[error("Contribution info is not valid: {0}")]
    InvalidContributionInfo(String),
    #[error("The required access secret is either missing or invalid")]
    InvalidSecret,
    #[error("Header {0} is badly formatted")]
    InvalidHeader(&'static str),
    #[error("Updated tokens for current cohort don't match the old ones")]
    InvalidNewTokens,
    #[error("Request's signature is invalid")]
    InvalidSignature,
    #[error("Authentification token for cohort {0} is invalid")]
    InvalidToken(usize),
    #[error("Authentification token has an invalid token format (hexadecimal 10 bytes)")]
    InvalidTokenFormat,
    #[error("Io Error: {0}")]
    IoError(String),
    #[error("Checksum of body doesn't match the expected one: expc {0}, act: {1}")]
    MismatchingChecksum(String, String),
    #[error("The required {0} header was missing from the incoming request")]
    MissingRequiredHeader(&'static str),
    #[error("Couldn't verify signature because of missing signing key")]
    MissingSigningKey,
    #[error("Couldn't parse string to int: {0}")]
    ParseError(#[from] std::num::ParseIntError),
    #[error("Thread panicked: {0}")]
    RuntimeError(#[from] task::JoinError),
    #[error("Error with S3: {0}")]
    S3Error(#[from] S3Error),
    #[error("Error with Serde: {0}")]
    SerdeError(String),
    #[error("Error while terminating the ceremony: {0}")]
    ShutdownError(String),
    #[error("The participant {0} is not allowed to access the endpoint {1} because of: {2}")]
    UnauthorizedParticipant(Participant, String, String),
    #[error("Could not find contributor with public key {0}")]
    UnknownContributor(String),
    #[error("Could not find the provided Task {0} in coordinator state")]
    UnknownTask(Task),
    #[error("Digest of request's body is not base64 encoded: {0}")]
    WrongDigestEncoding(#[from] base64::DecodeError),
}

impl<'r> Responder<'r, 'static> for ResponseError {
    fn respond_to(self, _request: &'r Request<'_>) -> rocket::response::Result<'static> {
        let response = format!("{}", self);
        let mut builder = Response::build();

        let response_code = match self {
            ResponseError::CeremonyIsOver => Status::Unauthorized,
            ResponseError::InvalidHeader(_) => Status::BadRequest,
            ResponseError::InvalidSecret => Status::Unauthorized,
            ResponseError::InvalidSignature => Status::BadRequest,
            ResponseError::InvalidToken(_) => Status::Unauthorized,
            ResponseError::InvalidTokenFormat => Status::BadRequest,
            ResponseError::MismatchingChecksum(_, _) => Status::BadRequest,
            ResponseError::MissingRequiredHeader(h) if h == CONTENT_LENGTH_HEADER => Status::LengthRequired,
            ResponseError::MissingRequiredHeader(_) => Status::BadRequest,
            ResponseError::MissingSigningKey => Status::BadRequest,
            ResponseError::SerdeError(_) => Status::UnprocessableEntity,
            ResponseError::UnauthorizedParticipant(_, _, _) => Status::Unauthorized,
            ResponseError::WrongDigestEncoding(_) => Status::BadRequest,
            _ => Status::InternalServerError,
        };

        builder
            .status(response_code)
            .header(ContentType::Text)
            .sized_body(response.len(), Cursor::new(response))
            .ok()
    }
}

type Result<T> = std::result::Result<T, ResponseError>;

// Custom catchers for Request/Data Guards. These remap custom error codes to the standard ones and call the ResponseError Responder to produce the response. The default catcher is mantained for non-custom errors

#[catch(452)]
pub fn invalid_signature() -> ResponseError {
    ResponseError::InvalidSignature
}

#[catch(453)]
pub fn unauthorized(req: &Request) -> ResponseError {
    let participant = req.local_cache(|| Participant::new_contributor(UNKNOWN));
    let (endpoint, cause) = req.local_cache(|| (String::from(UNKNOWN), String::from(UNKNOWN)));

    ResponseError::UnauthorizedParticipant(participant.clone(), endpoint.to_owned(), cause.to_owned())
}

#[catch(454)]
pub fn missing_required_header(req: &Request) -> ResponseError {
    let header = req.local_cache(|| UNKNOWN);
    ResponseError::MissingRequiredHeader(header)
}

#[catch(455)]
pub fn unprocessable_entity(req: &Request) -> ResponseError {
    let message = req.local_cache(|| UNKNOWN.to_string());
    ResponseError::SerdeError(message.to_string())
}

#[catch(456)]
pub fn mismatching_checksum(req: &Request) -> ResponseError {
    let (expected, actual) = req.local_cache(|| (UNKNOWN.to_string(), UNKNOWN.to_string()));
    ResponseError::MismatchingChecksum(expected.to_owned(), actual.to_owned())
}

#[catch(457)]
pub fn invalid_header(req: &Request) -> ResponseError {
    let header = req.local_cache(|| UNKNOWN);
    ResponseError::InvalidHeader(header)
}

#[catch(512)]
pub fn io_error(req: &Request) -> ResponseError {
    let message = req.local_cache(|| UNKNOWN.to_string());
    ResponseError::IoError(message.to_owned())
}

/// Content info
pub struct RequestContent<'a> {
    len: usize,
    digest: Cow<'a, str>,
}

impl<'a> RequestContent<'a> {
    pub fn new<T>(len: usize, digest: T) -> Self
    where
        T: AsRef<[u8]>,
    {
        Self {
            len,
            digest: base64::encode(digest).into(),
        }
    }

    /// Returns struct correctly formatted for the http header
    pub fn to_header(&self) -> (usize, String) {
        (self.len, format!("sha-256={}", self.digest))
    }

    /// Constructs from request's headers
    fn try_from_header(len: &str, digest: &'a str) -> Result<Self> {
        let digest = digest
            .split_once('=')
            .ok_or(ResponseError::InvalidHeader(BODY_DIGEST_HEADER))?
            .1;

        // Check encoding
        base64::decode(digest)?;
        let len = len
            .parse()
            .map_err(|_| ResponseError::InvalidHeader(CONTENT_LENGTH_HEADER))?;

        Ok(Self {
            len,
            digest: digest.into(),
        })
    }
}

/// The headers involved in the signature of the request.
#[derive(Default)]
pub struct SignatureHeaders<'r> {
    pub pubkey: &'r str,
    pub content: Option<RequestContent<'r>>,
    pub signature: Option<Cow<'r, str>>,
}

impl<'r> SignatureHeaders<'r> {
    /// Produces the message on which to compute the signature
    pub fn to_string(&self) -> Cow<'_, str> {
        match &self.content {
            Some(content) => format!("{}{}{}", self.pubkey, content.len, content.digest).into(),
            None => self.pubkey.into(),
        }
    }

    pub fn new(pubkey: &'r str, content: Option<RequestContent<'r>>, signature: Option<Cow<'r, str>>) -> Self {
        Self {
            pubkey,
            content,
            signature,
        }
    }

    fn try_verify_signature(&self) -> Result<bool> {
        match &self.signature {
            Some(sig) => Ok(Production.verify(self.pubkey, &self.to_string(), &sig)),
            None => Err(ResponseError::MissingSigningKey),
        }
    }
}

impl<'r> TryFrom<&'r Request<'_>> for SignatureHeaders<'r> {
    type Error = ResponseError;

    fn try_from(request: &'r Request<'_>) -> std::result::Result<Self, Self::Error> {
        let headers = request.headers();
        let mut body: Option<RequestContent> = None;

        let pubkey = headers
            .get_one(PUBKEY_HEADER)
            .ok_or(ResponseError::InvalidHeader(PUBKEY_HEADER))?;
        let sig = headers
            .get_one(SIGNATURE_HEADER)
            .ok_or(ResponseError::InvalidHeader(SIGNATURE_HEADER))?;

        // If post request, also get the hash of body from header (if any and if base64 encoded)
        if request.method() == rocket::http::Method::Post {
            if let Some(s) = headers.get_one(BODY_DIGEST_HEADER) {
                let content_length = headers
                    .get_one(CONTENT_LENGTH_HEADER)
                    .ok_or(ResponseError::InvalidHeader(CONTENT_LENGTH_HEADER))?;
                let content = RequestContent::try_from_header(content_length, s)?;

                body = Some(content);
            }
        }

        Ok(SignatureHeaders::new(pubkey, body, Some(sig.into())))
    }
}

trait VerifySignature<'r> {
    // Workaround to implement a single method on a foreign type instead of newtype pattern
    fn verify_signature(&'r self) -> Result<&str>;
}

impl<'r> VerifySignature<'r> for Request<'_> {
    /// Check signature of request and return the pubkey of the participant
    fn verify_signature(&'r self) -> Result<&str> {
        let headers = SignatureHeaders::try_from(self)?;

        match headers.try_verify_signature()? {
            true => Ok(headers.pubkey),
            false => Err(ResponseError::InvalidSignature),
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Participant {
    type Error = ResponseError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.verify_signature() {
            Ok(pubkey) => Outcome::Success(Participant::new_contributor(pubkey)),
            Err(e) => Outcome::Failure((Status::new(452), e)),
        }
    }
}

/// Implements the signature verification on the incoming unknown contributor request via [`FromRequest`].
pub struct NewParticipant {
    participant: Participant,
    ip_address: Option<IpAddr>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for NewParticipant {
    type Error = ResponseError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let pubkey = match request.verify_signature() {
            Ok(h) => h,
            Err(e) => return Outcome::Failure((Status::new(452), e)),
        };

        // Check that the signature comes from an unknown contributor
        let coordinator = request
            .guard::<&State<Coordinator>>()
            .await
            .succeeded()
            .expect("Managed state should always be retrievable");
        let participant = Participant::new_contributor(pubkey);
        let ip_address = request.client_ip();

        if let Err(e) = coordinator
            .read()
            .await
            .state()
            .add_to_queue_checks(&participant, ip_address.as_ref())
        {
            // Cache error data for the error catcher
            request.local_cache(|| participant.clone());
            request.local_cache(|| (request.uri().to_string(), e.to_string()));

            return Outcome::Failure((
                Status::new(453),
                ResponseError::UnauthorizedParticipant(participant, request.uri().to_string(), e.to_string()),
            ));
        }

        Outcome::Success(Self {
            participant,
            ip_address,
        })
    }
}

/// Implements the signature verification on the incoming current contributor request via [`FromRequest`].
pub struct CurrentContributor(Participant);

impl Deref for CurrentContributor {
    type Target = Participant;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for CurrentContributor {
    type Error = ResponseError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let pubkey = match request.verify_signature() {
            Ok(h) => h,
            Err(e) => return Outcome::Failure((Status::new(452), e)),
        };

        // Check that the signature comes from the current contributor by matching the public key
        let coordinator = request
            .guard::<&State<Coordinator>>()
            .await
            .succeeded()
            .expect("Managed state should always be retrievable");
        let participant = Participant::new_contributor(pubkey);

        let read_lock = coordinator.read().await;
        if !read_lock.is_current_contributor(&participant) {
            // Cache error data for the error catcher
            let error_msg = {
                if read_lock.is_banned_participant(&participant) {
                    String::from("Participant has been banned from the ceremony")
                } else if read_lock.is_dropped_participant(&participant) {
                    String::from("Participant has been dropped from the ceremony")
                } else {
                    String::from("Participant is not the current contributor")
                }
            };
            drop(read_lock);

            request.local_cache(|| participant.clone());
            request.local_cache(|| (request.uri().to_string(), error_msg.clone()));

            return Outcome::Failure((
                Status::new(453),
                ResponseError::UnauthorizedParticipant(participant, request.uri().to_string(), error_msg),
            ));
        }

        Outcome::Success(Self(participant))
    }
}

/// Implements the secret token verification on the incoming server request via [`FromRequest`]. Used to restrict access to endpoints only when headers contain the valid secret.
/// Can be used as an alternative to [`ServerAuth`] when the body of the request carries no data (and thus doesn't need a signature on that)
pub struct Secret;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Secret {
    type Error = ResponseError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.headers().get_one(ACCESS_SECRET_HEADER) {
            Some(secret) if secret == *ACCESS_SECRET => Outcome::Success(Self),
            _ => Outcome::Failure((
                Status::new(401),
                ResponseError::InvalidSecret,
            ))
        }
    }
}


/// Implements the signature verification on the incoming server request via [`FromRequest`].
pub struct ServerAuth;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ServerAuth {
    type Error = ResponseError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let pubkey = match request.verify_signature() {
            Ok(h) => h,
            Err(e) => return Outcome::Failure((Status::new(452), e)),
        };

        // Check that the signature comes from the coordinator by matching the default verifier key
        let coordinator = request
            .guard::<&State<Coordinator>>()
            .await
            .succeeded()
            .expect("Managed state should always be retrievable");
        let verifier = Participant::new_verifier(pubkey);

        if verifier != coordinator.read().await.environment().coordinator_verifiers()[0] {
            // Cache error data for the error catcher
            let error_msg = String::from("Not the coordinator's verifier");
            request.local_cache(|| verifier.clone());
            request.local_cache(|| (request.uri().to_string(), error_msg.clone()));

            return Outcome::Failure((
                Status::new(453),
                ResponseError::UnauthorizedParticipant(verifier, request.uri().to_string(), error_msg),
            ));
        }

        Outcome::Success(Self)
    }
}

/// Type to handle lazy deserialization of json encoded inputs.
pub struct LazyJson<T>(T);

impl<T> Deref for LazyJson<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for LazyJson<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[rocket::async_trait]
impl<'r, T: DeserializeOwned> FromData<'r> for LazyJson<T> {
    type Error = ResponseError;

    async fn from_data(req: &'r Request<'_>, data: rocket::data::Data<'r>) -> rocket::data::Outcome<'r, Self> {
        // Check that digest of body is the expected one
        let headers = req.headers();
        let expected_digest = match headers.get_one(BODY_DIGEST_HEADER) {
            Some(h) => h,
            None => {
                // Cache error data for the error catcher
                req.local_cache(|| BODY_DIGEST_HEADER.to_string());

                return rocket::data::Outcome::Failure((
                    Status::new(454),
                    ResponseError::MissingRequiredHeader(BODY_DIGEST_HEADER),
                ));
            }
        };

        let content_length = match headers.get_one(CONTENT_LENGTH_HEADER) {
            Some(h) => h,
            None => {
                // Cache error data for the error catcher
                req.local_cache(|| CONTENT_LENGTH_HEADER.to_string());

                return rocket::data::Outcome::Failure((
                    Status::new(454),
                    ResponseError::MissingRequiredHeader(CONTENT_LENGTH_HEADER),
                ));
            }
        };

        let expected_content = match RequestContent::try_from_header(content_length, expected_digest) {
            Ok(c) => c,
            Err(e) => {
                // Cache error data for the error catcher
                let header = match e {
                    ResponseError::InvalidHeader(h) => h,
                    _ => UNKNOWN,
                };
                req.local_cache(|| header);

                return rocket::data::Outcome::Failure((Status::new(457), e));
            }
        };

        let body = match data.open(expected_content.len.into()).into_bytes().await {
            Ok(bytes) => bytes.into_inner(),
            Err(e) => {
                // Cache error data for the error catcher
                req.local_cache(|| e.to_string());

                return rocket::data::Outcome::Failure((Status::new(512), ResponseError::IoError(e.to_string())));
            }
        };

        let mut hasher = Sha256::new();
        hasher.update(&body);
        let digest = base64::encode(hasher.finalize());
        if digest != expected_content.digest {
            // Cache error data for the error catcher
            req.local_cache(|| (expected_digest.to_owned(), expected_content.digest.to_string()));

            return rocket::data::Outcome::Failure((
                Status::new(456),
                ResponseError::MismatchingChecksum(expected_digest.to_owned(), expected_content.digest.to_string()),
            ));
        }

        // Deserialize data and pass it to the request handler
        match serde_json::from_slice::<T>(&body) {
            Ok(obj) => rocket::data::Outcome::Success(LazyJson(obj)),
            Err(e) => {
                // Cache error data for the error catcher
                req.local_cache(|| (e.to_string()));
                rocket::data::Outcome::Failure((Status::new(455), ResponseError::SerdeError(e.to_string())))
            }
        }
    }
}

/// The status of the contributor related to the current round.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ContributorStatus {
    Queue(u64, u64),
    Round,
    Finished,
    Banned,
    Other,
}

/// Request to post a [Chunk](`crate::objects::Chunk`).
#[derive(Clone, Deserialize, Serialize)]
pub struct PostChunkRequest {
    round_height: u64,
    contribution_locator: ContributionLocator,
    contribution_signature_locator: ContributionSignatureLocator,
}

impl PostChunkRequest {
    pub fn new(
        round_height: u64,
        contribution_locator: ContributionLocator,
        contribution_signature_locator: ContributionSignatureLocator,
    ) -> Self {
        Self {
            round_height,
            contribution_locator,
            contribution_signature_locator,
        }
    }
}

/// Checks the validity of the token for the ceremony.
async fn token_check(coordinator: Coordinator, token: &String) -> Result<()> {
    // Check if the token's format is correct
    let regex = Regex::new(TOKEN_REGEX).unwrap();

    if !regex.is_match(token) {
        return Err(ResponseError::InvalidTokenFormat);
    }

    // Calculate the cohort number
    let read_lock = coordinator.read().await;
    let cohort = read_lock.state().get_cohort();
    let tokens = match read_lock.state().tokens(cohort) {
        Some(t) => t,
        None => return Err(ResponseError::CeremonyIsOver),
    };

    if !tokens.contains(token) {
        return Err(ResponseError::InvalidToken(cohort));
    }

    Ok(())
}

//
// -- REST API ENDPOINTS --
//

/// Add the incoming contributor to the queue of contributors.
#[post("/contributor/join_queue", format = "json", data = "<token>")]
pub async fn join_queue(
    coordinator: &State<Coordinator>,
    new_participant: NewParticipant,
    token: LazyJson<String>,
) -> Result<()> {
    token_check(coordinator.deref().to_owned(), &token).await?;

    let mut write_lock = (*coordinator).clone().write_owned().await;

    task::spawn_blocking(move || {
        write_lock.add_to_queue(new_participant.participant, new_participant.ip_address, 10)
    })
    .await?.map_err(|e| ResponseError::CoordinatorError(e))
}

/// Lock a [Chunk](`crate::objects::Chunk`) in the ceremony. This should be the first function called when attempting to contribute to a chunk. Once the chunk is locked, it is ready to be downloaded.
#[get("/contributor/lock_chunk", format = "json")]
pub async fn lock_chunk(
    coordinator: &State<Coordinator>,
    participant: CurrentContributor,
) -> Result<Json<LockedLocators>> {
    let mut write_lock = (*coordinator).clone().write_owned().await;
    match task::spawn_blocking(move || write_lock.try_lock(&participant)).await? {
        Ok((_, locked_locators)) => Ok(Json(locked_locators)),
        Err(e) => Err(ResponseError::CoordinatorError(e)),
    }
}

/// Get the challenge key on Amazon S3 from the [Coordinator](`crate::Coordinator`).
#[post("/contributor/challenge", format = "json", data = "<round_height>")]
pub async fn get_challenge_url(
    coordinator: &State<Coordinator>,
    _participant: CurrentContributor,
    round_height: LazyJson<u64>,
) -> Result<Json<String>> {
    let s3_ctx = S3Ctx::new().await?;
    let key = format!("round_{}/chunk_0/contribution_0.verified", *round_height);

    // If challenge is already on S3 (round rollback) immediately return the key
    if let Some(url) = s3_ctx.get_challenge_url(key.clone()).await {
        return Ok(Json(url));
    }

    // Since we don't chunk the parameters, we have one chunk and one allowed contributor per round. Thus the challenge will always be located at round_{i}/chunk_0/contribution_0.verified
    // For example, the 1st challenge (after the initialization) is located at round_1/chunk_0/contribution_0.verified
    let read_lock = (*coordinator).clone().read_owned().await;
    let challenge = match task::spawn_blocking(move || read_lock.get_challenge(*round_height, 0, 0, true)).await? {
        Ok(challenge) => challenge,
        Err(e) => return Err(ResponseError::CoordinatorError(e)),
    };

    // Upload challenge to S3 and return url
    let url = s3_ctx.upload_challenge(key, challenge).await?;

    Ok(Json(url))
}

/// Request the urls where to upload a [Chunk](`crate::objects::Chunk`) contribution and the ContributionFileSignature.
#[post("/upload/chunk", format = "json", data = "<round_height>")]
pub async fn get_contribution_url(
    _participant: CurrentContributor,
    round_height: LazyJson<u64>,
) -> Result<Json<(String, String)>> {
    let contrib_key = format!("round_{}/chunk_0/contribution_1.unverified", *round_height);
    let contrib_sig_key = format!("round_{}/chunk_0/contribution_1.unverified.signature", *round_height);

    // Prepare urls for the upload
    let s3_ctx = S3Ctx::new().await?;
    let urls = s3_ctx.get_contribution_urls(contrib_key, contrib_sig_key);

    Ok(Json(urls))
}

/// Notify the [Coordinator](`crate::Coordinator`) of a finished and uploaded [Contribution](`crate::objects::Contribution`). This will unlock the given [Chunk](`crate::objects::Chunk`).
#[post(
    "/contributor/contribute_chunk",
    format = "json",
    data = "<contribute_chunk_request>"
)]
pub async fn contribute_chunk(
    coordinator: &State<Coordinator>,
    participant: CurrentContributor,
    contribute_chunk_request: LazyJson<PostChunkRequest>,
) -> Result<()> {
    // Download contribution and its signature from S3 to local disk from the provided Urls
    let s3_ctx = S3Ctx::new().await?;
    let (contribution, contribution_sig) = s3_ctx.get_contribution(contribute_chunk_request.round_height).await?;
    let mut write_lock = (*coordinator).clone().write_owned().await;

    task::spawn_blocking(move || {
        write_lock.write_contribution(contribute_chunk_request.contribution_locator, contribution)?;
        write_lock.write_contribution_file_signature(
            contribute_chunk_request.contribution_signature_locator,
            serde_json::from_slice(&contribution_sig)?,
        )?;
        write_lock.try_contribute(&participant, 0) // Only 1 chunk per round, chunk_id is always 0
    })
    .await?
    .map_or_else(|e| Err(ResponseError::CoordinatorError(e)), |_| Ok(()))
}

/// Performs the update of the [Coordinator](`crate::Coordinator`)
pub async fn perform_coordinator_update(coordinator: Coordinator) -> Result<()> {
    let mut write_lock = coordinator.clone().write_owned().await;

    task::spawn_blocking(move || write_lock.update()).await?.map_err(|e| ResponseError::CoordinatorError(e))
}

/// Update the [Coordinator](`crate::Coordinator`) state. This endpoint is accessible only by the coordinator itself.
#[cfg(debug_assertions)]
#[get("/update")]
pub async fn update_coordinator(coordinator: &State<Coordinator>, _auth: ServerAuth) -> Result<()> {
    perform_coordinator_update(coordinator.deref().to_owned()).await
}

/// Let the [Coordinator](`crate::Coordinator`) know that the participant is still alive and participating (or waiting to participate) in the ceremony.
#[post("/contributor/heartbeat")]
pub async fn heartbeat(coordinator: &State<Coordinator>, participant: Participant) -> Result<()> {
    coordinator.write().await.heartbeat(&participant).map_err(|e| ResponseError::CoordinatorError(e))
}

/// Stop the [Coordinator](`crate::Coordinator`) and shuts the server down. This endpoint is accessible only by the coordinator itself.
#[get("/stop")]
pub async fn stop_coordinator(coordinator: &State<Coordinator>, _auth: ServerAuth, shutdown: Shutdown) -> Result<()> {
    let mut write_lock = (*coordinator).clone().write_owned().await;
    let result = task::spawn_blocking(move || write_lock.shutdown()).await?;

    if let Err(e) = result {
        return Err(ResponseError::ShutdownError(format!("{}", e)));
    };

    // Shut Rocket server down
    shutdown.notify();

    Ok(())
}

/// Performs the verification of the pending contributions
pub async fn perform_verify_chunks(coordinator: Coordinator) -> Result<()> {
    // Get all the pending verifications, loop on each one of them and perform verification
    // Technically, since we don't chunk contributions and we only have one contribution per round, we will always get
    // one pending verification at max.
    let pending_verifications = coordinator.read().await.get_pending_verifications().to_owned();

    for (task, _) in pending_verifications {
        let mut write_lock = coordinator.clone().write_owned().await;
        // NOTE: we are going to rely on the single default verifier built in the coordinator itself,
        //  no external verifiers
        let verify_response = match task::spawn_blocking(move || write_lock.default_verify(&task)).await {
            Ok(inner) => inner.map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        };

        if let Err(e) = verify_response {
            warn!("Error while verifying a contribution: {}. Restarting the round...", e);
            // FIXME: the verify_masp function may panic but the program doesn't shut down because we are executing it on a separate thread. It would be better though to make that function return a Result instead of panicking. Revert of round should be moved inside default_verify

            // Get the participant who produced the contribution
            let mut write_lock = coordinator.clone().write_owned().await;
            return task::spawn_blocking(move || {
                let finished_contributor = write_lock
                    .state()
                    .current_round_finished_contributors()
                    .unwrap()
                    .first()
                    .unwrap()
                    .clone();

                // Reset the round to prevent a coordinator stall (the corrupted contribution is not automatically dropped)
                write_lock
                    .reset_round()
                    .map_err(|e| ResponseError::CoordinatorError(e))?;

                // Ban the participant who produced the invalid contribution. Must be banned after the reset beacuse one can't ban a finished contributor
                write_lock
                    .ban_participant(&finished_contributor)
                    .map_err(|e| ResponseError::CoordinatorError(e))
            })
            .await?;
        }
    }

    Ok(())
}

/// Verify all the pending contributions. This endpoint is accessible only by the coordinator itself.
#[cfg(debug_assertions)]
#[get("/verify")]
pub async fn verify_chunks(coordinator: &State<Coordinator>, _auth: ServerAuth) -> Result<()> {
    perform_verify_chunks(coordinator.deref().to_owned()).await
}

// TODO: add test for this new endpoint
/// Load new tokens to update the future cohorts. The `tokens` parameter is the serialized zip folder
#[post(
    "/update_cohorts",
    format = "json",
    data = "<tokens>"
)
]
pub async fn update_cohorts(coordinator: &State<Coordinator>, _auth: ServerAuth, tokens: LazyJson<Vec<u8>>) -> Result<()> {
    let reader = std::io::Cursor::new(tokens.clone());
    let mut zip = zip::ZipArchive::new(reader).map_err(|e| ResponseError::IoError(e.to_string()))?;
    let mut zip_clone = zip.clone();

    let new_tokens = task::spawn_blocking(move || -> Result<Vec<HashSet<String>>> {
        let mut cohorts: HashMap<String, Vec<u8>> = HashMap::new();
        let file_names: Vec<String> = zip_clone.file_names().map(|name| name.to_owned()).collect();

        for file in file_names {
            let mut buffer = Vec::new();
            zip_clone.by_name(file.as_str()).map_err(|e| ResponseError::IoError(e.to_string()))?.read_to_end(&mut buffer).map_err(|e| ResponseError::IoError(e.to_string()))?;
            cohorts.insert(file, buffer);
        }

        Ok(CoordinatorState::load_tokens_from_bytes(&cohorts))
    }).await.unwrap()?;

    // Check that the new tokens for the current cohort match the old ones (to prevent inconsistencies during contributions in the current cohort)
    let read_lock = coordinator.read().await;
    let cohort = read_lock.state().get_cohort();
    let old_tokens = match read_lock.state().tokens(cohort) {
        Some(t) => t,
        None => return Err(ResponseError::CeremonyIsOver),
    };

    match new_tokens.get(cohort) {
        Some(new_tokens) if new_tokens.len() == old_tokens.len() => {
            if new_tokens.difference(old_tokens).count() != 0 {
                return Err(ResponseError::InvalidNewTokens)
            }
        },
        _ => return Err(ResponseError::InvalidNewTokens),
    }
    drop(read_lock);

    // Persist new tokens to disk
    // New tokens MUST be written to file in case of a coordinator restart
    task::spawn_blocking(move || -> Result<()> {
        let mut zip_file = std::fs::File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(TOKENS_ZIP_FILE).map_err(|e| ResponseError::IoError(e.to_string()))?;

        zip_file.write_all(&tokens).map_err(|e| ResponseError::IoError(e.to_string()))?;

        if let Err(e) = std::fs::remove_dir_all(&*TOKENS_PATH) {
            // Log the error and continue
            warn!("Error while removing old tokens folder: {}", e);
        }
        zip.extract(&*TOKENS_PATH).map_err(|e| ResponseError::IoError(e.to_string()))?;

        Ok(())
    }).await.unwrap()?;

    // Update cohorts in coordinator's state
    coordinator.write().await.update_tokens(new_tokens);

    Ok(())
}

/// Get the queue status of the contributor.
#[get("/contributor/queue_status", format = "json")]
pub async fn get_contributor_queue_status(
    coordinator: &State<Coordinator>,
    participant: Participant,
) -> Json<ContributorStatus> {
    let contributor = participant.clone();

    let read_lock = (*coordinator).clone().read_owned().await;
    // Check that the contributor is authorized to lock a chunk in the current round.
    if task::spawn_blocking(move || read_lock.is_current_contributor(&contributor))
        .await
        .unwrap()
    {
        return Json(ContributorStatus::Round);
    }

    let read_lock = coordinator.read().await;

    if read_lock.is_queue_contributor(&participant) {
        let queue_size = read_lock.number_of_queue_contributors() as u64;

        let queue_position = match read_lock.state().queue_contributor_info(&participant) {
            Some((_, Some(round), _, _)) => round - read_lock.state().current_round_height(),
            Some((_, None, _, _)) => queue_size,
            None => return Json(ContributorStatus::Other),
        };

        return Json(ContributorStatus::Queue(queue_position, queue_size));
    }

    if read_lock.is_finished_contributor(&participant) {
        return Json(ContributorStatus::Finished);
    }

    if read_lock.is_banned_participant(&participant) {
        return Json(ContributorStatus::Banned);
    }

    // Not in the queue, not finished, nor in the current round
    Json(ContributorStatus::Other)
}

/// Write [`ContributionInfo`] to disk
#[post("/contributor/contribution_info", format = "json", data = "<request>")]
pub async fn post_contribution_info(
    coordinator: &State<Coordinator>,
    participant: CurrentContributor,
    request: LazyJson<ContributionInfo>,
) -> Result<()> {
    // Validate info
    if request.public_key != participant.address() {
        return Err(ResponseError::InvalidContributionInfo(format!(
            "Public key in info {} doesnt' match the participant one {}",
            request.public_key,
            participant.address()
        )));
    }

    let current_round_height = match coordinator.read().await.current_round_height() {
        Ok(r) => r,
        Err(e) => return Err(ResponseError::CoordinatorError(e)),
    };

    if current_round_height != request.ceremony_round {
        // NOTE: validation of round_height matters in case of a round rollback
        return Err(ResponseError::InvalidContributionInfo(format!(
            "Round height in info {} doesnt' match the current round height {}",
            request.ceremony_round, current_round_height
        )));
    }

    // Write contribution info and summary to file
    let mut write_lock = (*coordinator).clone().write_owned().await;

    task::spawn_blocking(move || {
        write_lock.write_contribution_info(request.clone())?;

        write_lock.update_contribution_summary(request.0.into())
    })
    .await?
    .map_err(|e| ResponseError::CoordinatorError(e))
}

/// Retrieve the contributions' info. This endpoint is accessible by anyone and does not require a signed request.
#[get("/contribution_info")]
pub async fn get_contributions_info(coordinator: &State<Coordinator>) -> Result<Vec<u8>> {
    let read_lock = (*coordinator).clone().read_owned().await;
    let summary = task::spawn_blocking(move || read_lock.storage().get_contributions_summary())
        .await?
        .map_err(|e| ResponseError::CoordinatorError(e))?;

    Ok(summary)
}

/// Retrieve the coordinator.json status file
#[get("/coordinator_status")]
pub async fn get_coordinator_state(coordinator: &State<Coordinator>, _auth: Secret) -> Result<Vec<u8>> {
    let read_lock = (*coordinator).clone().read_owned().await;
    let state = task::spawn_blocking(move || read_lock.storage().get_coordinator_state())
        .await?
        .map_err(|e| ResponseError::CoordinatorError(e))?;

    Ok(state)
}

/// Retrieve healthcheck info. This endpoint is accessible by anyone and does not require a signed request.
#[get("/healthcheck", format = "json")]
pub async fn get_healthcheck() -> Result<String> {
    let content = fs::read_to_string(HEALTH_PATH.as_str())
        .await
        .map_err(|e| ResponseError::IoError(e.to_string()))?;

    Ok(content)
}
