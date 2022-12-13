//  NOTE: these tests must be run with --test-threads=1 due to the disk storage
//	being stored at the same path for all the test instances causing a conflict.
//	It could be possible to define a separate location (base_dir) for every test
//	but it's simpler to just run the tests sequentially.
//  NOTE: these tests require the phase1radix files to be placed in the phase2-coordinator folder

use std::{
    io::Write,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use blake2::Digest;
use phase2_coordinator::{
    authentication::{KeyPair, Production, Signature},
    commands::{Computation, RandomSource},
    coordinator_state::CoordinatorState,
    environment::Testing,
    objects::{ContributionInfo, LockedLocators, TrimmedContributionInfo},
    rest,
    rest_utils::{
        self, ContributorStatus, PostChunkRequest, ACCESS_SECRET_HEADER, BODY_DIGEST_HEADER, CONTENT_LENGTH_HEADER,
        PUBKEY_HEADER, SIGNATURE_HEADER, TOKENS_ZIP_FILE,
    },
    storage::{ContributionLocator, ContributionSignatureLocator, Object},
    testing::coordinator,
    ContributionFileSignature, ContributionState, Coordinator, Participant,
};
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use rocket::{
    catchers,
    http::{ContentType, Header, Status},
    local::blocking::{Client, LocalRequest},
    routes,
    tokio::sync::RwLock,
    Build, Rocket,
};
use serde::Serialize;
use sha2::Sha256;
use zip::write::FileOptions;

const ROUND_HEIGHT: u64 = 1;

struct TestParticipant {
    _inner: Participant,
    address: IpAddr,
    keypair: KeyPair,
    locked_locators: Option<LockedLocators>,
}

struct TestCtx {
    rocket: Rocket<Build>,
    contributors: Vec<TestParticipant>,
    unknown_participant: TestParticipant,
    coordinator: TestParticipant,
    // Keep TempDir in scope for some tests
    _tokens_tmp_dir: tempfile::TempDir,
}

/// Build the rocket server for testing with the proper configuration.
fn build_context() -> TestCtx {
    std::env::set_var("TOKEN_BLACKLIST", "true");
    std::env::set_var("NAMADA_MPC_IP_BAN", "true");

    // Reset storage to prevent state conflicts between tests and initialize test environment
    let environment = coordinator::initialize_test_environment(&Testing::default().into());

    // Create token file
    // Need a fixed-name temp dir because of the lazy_static variables based on env
    // Sometimes TempDir is not deleted correctly at drop, need to manually cancel the directory if it sill exists from a previous run
    let os_temp_dir = std::env::temp_dir();
    std::fs::remove_dir_all(os_temp_dir.join("my-temporary-dir")).ok();
    let tmp_dir = tempfile::Builder::new()
        .prefix("my-temporary-dir")
        .rand_bytes(0)
        .tempdir()
        .unwrap();

    let file_path = tmp_dir.path().join("namada_tokens_cohort_1.json");
    let mut token_file = std::fs::File::create(file_path).unwrap();
    token_file
        .write_all("[\"9nFeNpukSn1eVwNc2vkfP7rdLh2njm5ewmCGxSLTW3GYmKP51fKjbRUvHDmntjEaQiq7iFux9tumgWEWVHwHQCs31oitpqBpMWpMydo1DnuFyLpsD6C\", \"9nFeNpukSn1eVwNc2vkfP7sQsLG3oS7623phb2Zzc23GAdXjuby4XAbwbWbx1uNaYrZorVLio4ZSt3u95sgi4fsS8hiZ3XkEttBF6q4461dGpoWv7ek\", \"9nFeNpukSn1eVwNc2vkfP8SP4HrxTh9F86CY5pNWw8RF3jZa91q2i3yvE7ugpn9w2RzoZBZrdskgckmvJuVKq6ZWxfV8TepZYFd9SeARGHexi7tGGV2\"]".as_bytes())
        .unwrap();
    std::env::set_var("NAMADA_TOKENS_PATH", tmp_dir.path());

    // Instantiate the coordinator
    let mut coordinator = Coordinator::new(environment, Arc::new(Production)).unwrap();

    let keypair1 = KeyPair::new();
    let keypair2 = KeyPair::new();
    let keypair3 = KeyPair::new();

    let contributor1 = Participant::new_contributor(keypair1.pubkey());
    let contributor2 = Participant::new_contributor(keypair2.pubkey());
    let unknown_contributor = Participant::new_contributor(keypair3.pubkey());

    let coordinator_ip = IpAddr::V4("0.0.0.0".parse().unwrap());
    let contributor1_ip = IpAddr::V4("0.0.0.1".parse().unwrap());
    let contributor2_ip = IpAddr::V4("0.0.0.2".parse().unwrap());
    let unknown_contributor_ip = IpAddr::V4("0.0.0.3".parse().unwrap());

    let token = String::from(
        "9nFeNpukSn1eVwNc2vkfP7rdLh2njm5ewmCGxSLTW3GYmKP51fKjbRUvHDmntjEaQiq7iFux9tumgWEWVHwHQCs31oitpqBpMWpMydo1DnuFyLpsD6C",
    );

    coordinator.initialize().unwrap();
    let coordinator_keypair = KeyPair::custom_new(
        coordinator.environment().default_verifier_signing_key(),
        coordinator.environment().coordinator_verifiers()[0].address(),
    );

    let coord_verifier = TestParticipant {
        _inner: coordinator.environment().coordinator_verifiers()[0].clone(),
        address: coordinator_ip,
        keypair: coordinator_keypair,
        locked_locators: None,
    };

    coordinator
        .add_to_queue(contributor1.clone(), Some(contributor1_ip.clone()), token, 10)
        .unwrap();
    coordinator.update().unwrap();

    let (_, locked_locators) = coordinator.try_lock(&contributor1).unwrap();

    let coordinator: Arc<RwLock<Coordinator>> = Arc::new(RwLock::new(coordinator));

    let rocket = rocket::build()
        .mount(
            "/",
            routes![
                rest::join_queue,
                rest::lock_chunk,
                rest::contribute_chunk,
                rest::update_coordinator,
                rest::heartbeat,
                rest::stop_coordinator,
                rest::verify_chunks,
                rest::get_contributor_queue_status,
                rest::post_contribution_info,
                rest::get_contributions_info,
                rest::get_healthcheck,
                rest::get_contribution_url,
                rest::get_challenge_url,
                rest::get_coordinator_state,
                rest::update_cohorts,
                rest::post_attestation
            ],
        )
        .manage(coordinator)
        .register(
            "/",
            catchers![
                rest_utils::invalid_signature,
                rest_utils::unauthorized,
                rest_utils::missing_required_header,
                rest_utils::io_error,
                rest_utils::unprocessable_entity,
                rest_utils::mismatching_checksum,
                rest_utils::invalid_header
            ],
        );

    // Create participants
    let test_participant1 = TestParticipant {
        _inner: contributor1,
        address: contributor1_ip,
        keypair: keypair1,
        locked_locators: Some(locked_locators),
    };
    let test_participant2 = TestParticipant {
        _inner: contributor2,
        address: contributor2_ip,
        keypair: keypair2,
        locked_locators: None,
    };
    let unknown_participant = TestParticipant {
        _inner: unknown_contributor,
        address: unknown_contributor_ip,
        keypair: keypair3,
        locked_locators: None,
    };

    TestCtx {
        rocket,
        contributors: vec![test_participant1, test_participant2],
        unknown_participant,
        coordinator: coord_verifier,
        _tokens_tmp_dir: tmp_dir,
    }
}

/// Add headers and optional body to the request
fn set_request<'a, T>(mut req: LocalRequest<'a>, keypair: &'a KeyPair, body: Option<&T>) -> LocalRequest<'a>
where
    T: Serialize,
{
    let mut msg = keypair.pubkey().to_owned();
    req.add_header(Header::new(PUBKEY_HEADER, keypair.pubkey().to_owned()));

    if let Some(body) = body {
        // Body digest
        let json_body = serde_json::to_string(body).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&json_body);
        let digest = base64::encode(hasher.finalize());
        msg = format!("{}{}{}", msg, json_body.len(), &digest);
        req.add_header(Header::new(BODY_DIGEST_HEADER, format!("sha-256={}", digest)));

        // Body length
        req.add_header(Header::new(CONTENT_LENGTH_HEADER, json_body.len().to_string()));

        // Attach json serialized body
        req.add_header(ContentType::JSON);
        req = req.body(&json_body);
    }

    // Sign request
    let signature = Production.sign(keypair.sigkey(), &msg).unwrap();
    req.add_header(Header::new(SIGNATURE_HEADER, signature));

    req
}

#[test]
fn get_status() {
    let access_token = "test-access_token";
    std::env::set_var("ACCESS_SECRET", access_token);
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Retrieve coordinator.json file with valid token
    let mut req = client.get("/coordinator_status");
    req.add_header(Header::new(ACCESS_SECRET_HEADER, access_token));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_some());

    // Check deserialization
    let _status: CoordinatorState = response.into_json().unwrap();

    // Provide invalid token
    req = client.get("/coordinator_status");
    req.add_header(Header::new(ACCESS_SECRET_HEADER, "wrong token"));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());
}

fn get_serialized_tokens_zip(tokens: Vec<&str>) -> Vec<u8> {
    let w = std::io::Cursor::new(Vec::new());
    let mut zip_writer = zip::ZipWriter::new(w);

    for cohort in 0..tokens.len() {
        zip_writer
            .start_file(
                format!("namada_tokens_cohort_{}.json", cohort + 1),
                FileOptions::default(),
            )
            .unwrap();
        zip_writer.write(tokens[cohort].as_bytes()).unwrap();
    }

    zip_writer.finish().unwrap().into_inner()
}

#[test]
fn update_cohorts() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Check tokens.zip file presence only when correct input
    // Remove tokens.zip file if present
    std::fs::remove_file(TOKENS_ZIP_FILE).ok();

    // Create new tokens zip file
    let new_invalid_tokens = get_serialized_tokens_zip(vec![
        "[\"9nFeNpukSn1eVwNc2vkfP7rdLh2njm5ewmCGxSLTW3GYmKP51fKjbRUvHDmntjEaQiq7iFux9tumgWEWVHwHQCs31oitpqBpMWpMydo1DnuFyLpsD6C\", \"9nFeNpukSn1eVwNc2vkfP7sQsLG3oS7623phb2Zzc23GAdXjuby4XAbwbWbx1uNaYrZorVLio4ZSt3u95sgi4fsS8hiZ3XkEttBF6q4461dGpoWv7ek\"]",
    ]);

    // Wrong, request from non-coordinator participant
    let mut req = client.post("/update_cohorts");
    req = set_request::<Vec<u8>>(req, &ctx.contributors[0].keypair, Some(&new_invalid_tokens));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());
    assert!(std::fs::metadata(TOKENS_ZIP_FILE).is_err());

    // Wrong new tokens
    req = client.post("/update_cohorts");
    req = set_request::<Vec<u8>>(req, &ctx.coordinator.keypair, Some(&new_invalid_tokens));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::InternalServerError);
    assert!(response.body().is_some());
    assert!(std::fs::metadata(TOKENS_ZIP_FILE).is_err());

    // Valid new tokens
    let new_valid_tokens = get_serialized_tokens_zip(vec![
        "[\"9nFeNpukSn1eVwNc2vkfP7rdLh2njm5ewmCGxSLTW3GYmKP51fKjbRUvHDmntjEaQiq7iFux9tumgWEWVHwHQCs31oitpqBpMWpMydo1DnuFyLpsD6C\", \"9nFeNpukSn1eVwNc2vkfP7sQsLG3oS7623phb2Zzc23GAdXjuby4XAbwbWbx1uNaYrZorVLio4ZSt3u95sgi4fsS8hiZ3XkEttBF6q4461dGpoWv7ek\", \"9nFeNpukSn1eVwNc2vkfP8SP4HrxTh9F86CY5pNWw8RF3jZa91q2i3yvE7ugpn9w2RzoZBZrdskgckmvJuVKq6ZWxfV8TepZYFd9SeARGHexi7tGGV2\"]",
        "[\"9nFeNpukSn1eVwNc2vkfP8TAaw6DXNAgCNpxiQc437BxT3iF2xUMdo6wYQjqwxHwAZjVhQzdH3QMpJSbXvaDcnkVu6Ktt22AfYDypK2h72vuQK9fGNp\"]",
    ]);

    req = client.post("/update_cohorts");
    req = set_request::<Vec<u8>>(req, &ctx.coordinator.keypair, Some(&new_valid_tokens));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_none());
    assert!(std::fs::metadata(TOKENS_ZIP_FILE).is_ok());
}

#[test]
fn stop_coordinator() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Wrong, request from non-coordinator participant
    let mut req = client.get("/stop");
    req = set_request::<()>(req, &ctx.contributors[0].keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());

    // Shut the server down
    req = client.get("/stop");
    req = set_request::<()>(req, &ctx.coordinator.keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_none());
}

#[test]
fn get_healthcheck() {
    // Create status file
    let mut status_file = tempfile::NamedTempFile::new_in(".").unwrap();
    let file_content =
        "{\"hash\":\"2e7f10b5a96f9f1e8c959acbce08483ccd9508e1\",\"timestamp\":\"Tue Jun 21 10:28:35 CEST 2022\"}";
    status_file.write_all(file_content.as_bytes()).unwrap();
    std::env::set_var("HEALTH_PATH", status_file.path());

    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    let req = client.get("/healthcheck");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_some());

    // It's impossible to extract the String out of the Body struct of the response, need to pass through serde
    let response_body: serde_json::Value = response.into_json().unwrap();
    let response_str = serde_json::to_string(&response_body).unwrap();
    if response_str != file_content {
        panic!("JSON status content doesn't match the expected one")
    }
}

#[test]
fn get_contributor_queue_status() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Non-existing contributor key
    let mut req = client.get("/contributor/queue_status");
    req = set_request::<()>(req, &ctx.unknown_participant.keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    match response.into_json::<ContributorStatus>().unwrap() {
        ContributorStatus::Other => (),
        _ => panic!("Wrong ContributorStatus"),
    }

    // Ok
    req = client.get("/contributor/queue_status");
    req = set_request::<()>(req, &ctx.contributors[0].keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    match response.into_json::<ContributorStatus>().unwrap() {
        ContributorStatus::Round => (),
        _ => panic!("Wrong ContributorStatus"),
    }
}

#[test]
fn heartbeat() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Non-existing contributor key
    let mut req = client.post("/contributor/heartbeat");
    req = set_request::<()>(req, &ctx.unknown_participant.keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::InternalServerError);
    assert!(response.body().is_some());

    // Ok
    req = client.post("/contributor/heartbeat");
    req = set_request::<()>(req, &ctx.contributors[0].keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_none());
}

#[test]
fn update_coordinator() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Wrong, request comes from normal contributor
    let mut req = client.get("/update");
    req = set_request::<()>(req, &ctx.contributors[0].keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());

    // Ok, request comes from coordinator itself
    req = client.get("/update");
    req = set_request::<()>(req, &ctx.coordinator.keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_none());
}

#[test]
fn wrong_post_attestation() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Wrong, missing contribution
    let mut req = client.post("/contributor/attestation");
    req = set_request::<(u64, String)>(
        req,
        &ctx.contributors[0].keypair,
        Some(&(1, String::from("https://namada.net"))),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::InternalServerError);
    assert!(response.body().is_some());
}

#[test]
fn join_queue() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    let socket_address = SocketAddr::new(ctx.unknown_participant.address, 8080);

    // Wrong request, invalid token
    let mut req = client.post("/contributor/join_queue").remote(socket_address);
    req = set_request::<String>(
        req,
        &ctx.unknown_participant.keypair,
        Some(&format!(
            "9nFeNpukSn1eVwNc2vkfP8SP4HrxTh9F86CY5pNWw8RF3jZa91q2i3yvE7ugpn9w2RzoZBZrdskgckmvJuVKq6ZWxfV8TepZYFd9SeARGHexi7tGGV3"
        )),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());

    // Ok request
    req = client.post("/contributor/join_queue").remote(socket_address);
    req = set_request::<String>(
        req,
        &ctx.unknown_participant.keypair,
        Some(&format!(
            "9nFeNpukSn1eVwNc2vkfP7sQsLG3oS7623phb2Zzc23GAdXjuby4XAbwbWbx1uNaYrZorVLio4ZSt3u95sgi4fsS8hiZ3XkEttBF6q4461dGpoWv7ek"
        )),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_some());

    // Wrong request, IP already in queue
    req = client.post("/contributor/join_queue").remote(socket_address);
    req = set_request::<String>(
        req,
        &ctx.contributors[1].keypair,
        Some(&format!(
            "9nFeNpukSn1eVwNc2vkfP8SP4HrxTh9F86CY5pNWw8RF3jZa91q2i3yvE7ugpn9w2RzoZBZrdskgckmvJuVKq6ZWxfV8TepZYFd9SeARGHexi7tGGV2"
        )),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());

    // Wrong request, token already in queue
    let socket_address = SocketAddr::new(IpAddr::V4("0.0.0.4".parse().unwrap()), 8080);
    req = client.post("/contributor/join_queue").remote(socket_address);
    req = set_request::<String>(
        req,
        &ctx.contributors[1].keypair,
        Some(&format!(
            "9nFeNpukSn1eVwNc2vkfP7sQsLG3oS7623phb2Zzc23GAdXjuby4XAbwbWbx1uNaYrZorVLio4ZSt3u95sgi4fsS8hiZ3XkEttBF6q4461dGpoWv7ek"
        )),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());

    // Wrong request, already existing contributor
    req = client.post("/contributor/join_queue").remote(socket_address);
    req = set_request::<String>(
        req,
        &ctx.unknown_participant.keypair,
        Some(&format!(
            "9nFeNpukSn1eVwNc2vkfP8SP4HrxTh9F86CY5pNWw8RF3jZa91q2i3yvE7ugpn9w2RzoZBZrdskgckmvJuVKq6ZWxfV8TepZYFd9SeARGHexi7tGGV2"
        )),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());
}

/// Test wrong usage of lock_chunk.
#[test]
fn wrong_lock_chunk() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Wrong request, unknown participant
    let mut req = client.get("/contributor/lock_chunk");
    req = set_request::<u8>(req, &ctx.unknown_participant.keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());
}

/// Test wrong usage of get_challenge.
#[test]
fn wrong_get_challenge() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Wrong request, non-json body
    let req = client
        .post("/contributor/challenge")
        .header(ContentType::Text)
        .body("Wrong parameter type");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::NotFound);
    assert!(response.body().is_some());
}

/// Test wrong usage of post_contribution_chunk.
#[test]
fn wrong_post_contribution_chunk() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Wrong request, non-json body
    let mut req = client
        .post("/upload/chunk")
        .header(ContentType::Text)
        .body("Wrong parameter type");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::NotFound);
    assert!(response.body().is_some());

    // Wrong request json body format
    req = client.post("/upload/chunk");
    req = set_request(
        req,
        &ctx.contributors[0].keypair,
        Some(&String::from("Unexpected string")),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::UnprocessableEntity);
    assert!(response.body().is_some());
}

/// Test wrong usage of contribute_chunk.
#[test]
fn wrong_contribute_chunk() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Wrong request, non-json body
    let mut req = client
        .post("/contributor/contribute_chunk")
        .header(ContentType::Text)
        .body("Wrong parameter type");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::NotFound);
    assert!(response.body().is_some());

    // Wrong request json body format
    req = client.post("/contributor/contribute_chunk");
    req = set_request(
        req,
        &ctx.contributors[0].keypair,
        Some(&String::from("Unexpected string")),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::UnprocessableEntity);
    assert!(response.body().is_some());

    let c = ContributionLocator::new(ROUND_HEIGHT, 0, 1, false);
    let s = ContributionSignatureLocator::new(ROUND_HEIGHT, 0, 1, false);
    let r = PostChunkRequest::new(ROUND_HEIGHT, c, s);

    // Non-existing contributor key
    req = client.post("/contributor/contribute_chunk");
    req = set_request::<PostChunkRequest>(req, &ctx.unknown_participant.keypair, Some(&r));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());

    // Non-current-contributor
    req = client.post("/contributor/contribute_chunk");
    req = set_request(req, &ctx.contributors[1].keypair, Some(&r));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());
}

#[test]
fn wrong_verify() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Wrong, request from non-coordinator participant
    let mut req = client.get("/verify");
    req = set_request::<()>(req, &ctx.contributors[0].keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());
}

#[test]
fn wrong_post_contribution_info() {
    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");

    // Wrong request, non-json body
    let mut req = client
        .post("/contributor/contribution_info")
        .header(ContentType::Text)
        .body("Wrong parameter type");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::NotFound);
    assert!(response.body().is_some());

    // Wrong request json body format
    req = client.post("/contributor/contribution_info");
    req = set_request::<String>(
        req,
        &ctx.contributors[0].keypair,
        Some(&String::from("Unexpected string")),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::UnprocessableEntity);
    assert!(response.body().is_some());

    // Non-existing contributor key
    let contrib_info = ContributionInfo::default();
    req = client.post("/contributor/contribution_info");
    req = set_request::<ContributionInfo>(req, &ctx.unknown_participant.keypair, Some(&contrib_info));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());

    // Non-current-contributor participant
    let mut contrib_info = ContributionInfo::default();
    contrib_info.public_key = ctx.contributors[1].keypair.pubkey().to_owned();
    req = client.post("/contributor/contribution_info");
    req = set_request::<ContributionInfo>(req, &ctx.contributors[1].keypair, Some(&contrib_info));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());
}

/// Test a full contribution:
///
/// - get_challenge_url
/// - get_challenge
/// - get_contribution_url
/// - upload_chunk
/// - post_contributor_info
/// - post_contribution_chunk
/// - verify_chunk
/// - get_contributions_info
/// - Update cohorts' tokens
/// - join_queue with already contributed Ip
/// - join_queue with already contributed token
/// - Skip to second cohort
/// - Try joinin queue with expired token
/// - Try attestation
/// - Try joinin queue with correct token
///
#[test]
fn contribution() {
    const COHORT_TIME: u64 = 15;
    std::env::set_var("NAMADA_COHORT_TIME", COHORT_TIME.to_string()); // 15 seconds for each cohort
    use setup_utils::calculate_hash;

    let ctx = build_context();
    let client = Client::tracked(ctx.rocket).expect("Invalid rocket instance");
    let reqwest_client = reqwest::blocking::Client::new();
    let start_time = std::time::Instant::now();

    // Remove tokens.zip file if present
    std::fs::remove_file(TOKENS_ZIP_FILE).ok();

    // Get challenge url
    let _locked_locators = ctx.contributors[0].locked_locators.as_ref().unwrap();
    let mut req = client.post("/contributor/challenge");
    req = set_request::<u64>(req, &ctx.contributors[0].keypair, Some(&ROUND_HEIGHT));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_some());
    let challenge_url: String = response.into_json().unwrap();

    // Get challenge
    let challenge = reqwest_client
        .get(challenge_url)
        .send()
        .unwrap()
        .bytes()
        .unwrap()
        .to_vec();

    // Get contribution url
    req = client.post("/upload/chunk");
    req = set_request::<u64>(req, &ctx.contributors[0].keypair, Some(&ROUND_HEIGHT));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_some());
    let (chunk_url, sig_url): (String, String) = response.into_json().unwrap();

    // Upload chunk and signature
    let contribution_locator = ContributionLocator::new(ROUND_HEIGHT, 0, 1, false);
    let challenge_hash = calculate_hash(challenge.as_ref());

    let mut contribution: Vec<u8> = Vec::new();
    contribution.write_all(challenge_hash.as_slice()).unwrap();
    let entropy = RandomSource::Entropy(String::from("entropy"));
    Computation::contribute(&challenge, &mut contribution, &entropy).unwrap();

    // Initial contribution size is 2332 but the Coordinator expect ANOMA_BASE_FILE_SIZE. Extend to this size with trailing 0s
    let contrib_size = Object::anoma_contribution_file_size(ROUND_HEIGHT, 1);
    contribution.resize(contrib_size as usize, 0);

    let contribution_file_signature_locator = ContributionSignatureLocator::new(ROUND_HEIGHT, 0, 1, false);

    let response_hash = calculate_hash(contribution.as_ref());

    let contribution_state = ContributionState::new(challenge_hash.to_vec(), response_hash.to_vec(), None).unwrap();

    let sigkey = ctx.contributors[0].keypair.sigkey();
    let signature = Production
        .sign(sigkey, &contribution_state.signature_message().unwrap())
        .unwrap();

    let contribution_file_signature = ContributionFileSignature::new(signature, contribution_state).unwrap();

    let response = reqwest_client.put(chunk_url).body(contribution).send().unwrap();
    assert!(response.status().is_success());

    let response = reqwest_client
        .put(sig_url)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .body(serde_json::to_vec(&contribution_file_signature).unwrap())
        .send()
        .unwrap();
    assert!(response.status().is_success());

    // Post contribution info
    let mut contrib_info = ContributionInfo::default();
    contrib_info.full_name = Some(String::from("Test Name"));
    contrib_info.email = Some(String::from("test@mail.dev"));
    contrib_info.public_key = ctx.contributors[0].keypair.pubkey().to_owned();
    contrib_info.ceremony_round = ctx.contributors[0]
        .locked_locators
        .as_ref()
        .unwrap()
        .current_contribution()
        .round_height();
    contrib_info.try_sign(&ctx.contributors[0].keypair).unwrap();

    req = client.post("/contributor/contribution_info");
    req = set_request::<ContributionInfo>(req, &ctx.contributors[0].keypair, Some(&contrib_info));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_none());

    // Contribute
    let post_chunk = PostChunkRequest::new(ROUND_HEIGHT, contribution_locator, contribution_file_signature_locator);

    req = client.post("/contributor/contribute_chunk");
    req = set_request::<PostChunkRequest>(req, &ctx.contributors[0].keypair, Some(&post_chunk));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_none());

    // Verify chunk
    req = client.get("/verify");
    req = set_request::<()>(req, &ctx.coordinator.keypair, None);
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_none());

    // Get contributions info
    req = client.get("/contribution_info");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_some());

    let summary: Vec<TrimmedContributionInfo> = response.into_json().unwrap();
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0].public_key(), ctx.contributors[0].keypair.pubkey());
    assert!(!summary[0].is_another_machine());
    assert!(!summary[0].is_own_seed_of_randomness());
    assert_eq!(summary[0].ceremony_round(), 1);

    // Update cohorts
    assert!(std::fs::metadata(TOKENS_ZIP_FILE).is_err());
    let new_valid_tokens = get_serialized_tokens_zip(vec![
        "[\"9nFeNpukSn1eVwNc2vkfP7rdLh2njm5ewmCGxSLTW3GYmKP51fKjbRUvHDmntjEaQiq7iFux9tumgWEWVHwHQCs31oitpqBpMWpMydo1DnuFyLpsD6C\", \"9nFeNpukSn1eVwNc2vkfP7sQsLG3oS7623phb2Zzc23GAdXjuby4XAbwbWbx1uNaYrZorVLio4ZSt3u95sgi4fsS8hiZ3XkEttBF6q4461dGpoWv7ek\", \"9nFeNpukSn1eVwNc2vkfP8SP4HrxTh9F86CY5pNWw8RF3jZa91q2i3yvE7ugpn9w2RzoZBZrdskgckmvJuVKq6ZWxfV8TepZYFd9SeARGHexi7tGGV2\"]",
        "[\"9nFeNpukSn1eVwNc2vkfP8TAaw6DXNAgCNpxiQc437BxT3iF2xUMdo6wYQjqwxHwAZjVhQzdH3QMpJSbXvaDcnkVu6Ktt22AfYDypK2h72vuQK9fGNp\"]",
    ]);

    req = client.post("/update_cohorts");
    req = set_request::<Vec<u8>>(req, &ctx.coordinator.keypair, Some(&new_valid_tokens));
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_none());
    assert!(std::fs::metadata(TOKENS_ZIP_FILE).is_ok());

    // Join queue with already contributed Ip
    let socket_address = SocketAddr::new(ctx.contributors[0].address, 8080);

    req = client.post("/contributor/join_queue").remote(socket_address);
    req = set_request::<String>(
        req,
        &ctx.unknown_participant.keypair,
        Some(&format!(
            "9nFeNpukSn1eVwNc2vkfP8SP4HrxTh9F86CY5pNWw8RF3jZa91q2i3yvE7ugpn9w2RzoZBZrdskgckmvJuVKq6ZWxfV8TepZYFd9SeARGHexi7tGGV2"
        )),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());

    // Join queue with already contributed Token
    let socket_address = SocketAddr::new(ctx.unknown_participant.address, 8080);

    req = client.post("/contributor/join_queue").remote(socket_address);
    req = set_request::<String>(
        req,
        &ctx.unknown_participant.keypair,
        Some(&format!(
            "9nFeNpukSn1eVwNc2vkfP7rdLh2njm5ewmCGxSLTW3GYmKP51fKjbRUvHDmntjEaQiq7iFux9tumgWEWVHwHQCs31oitpqBpMWpMydo1DnuFyLpsD6C"
        )),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());

    // Skip to second cohort and try joining the queue with expired token
    let sleep_time = COHORT_TIME - start_time.elapsed().as_secs();
    std::thread::sleep(std::time::Duration::from_secs(sleep_time));

    req = client.post("/contributor/join_queue").remote(socket_address);
    req = set_request::<String>(
        req,
        &ctx.unknown_participant.keypair,
        Some(&format!(
            "9nFeNpukSn1eVwNc2vkfP7sQsLG3oS7623phb2Zzc23GAdXjuby4XAbwbWbx1uNaYrZorVLio4ZSt3u95sgi4fsS8hiZ3XkEttBF6q4461dGpoWv7ek"
        )),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());

    // Attestation

    // Wrong url format
    req = client.post("/contributor/attestation");
    req = set_request::<(u64, String)>(
        req,
        &ctx.contributors[0].keypair,
        Some(&(1, String::from("not_a_valid_url"))),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::InternalServerError);
    assert!(response.body().is_some());

    // Wrong round height
    req = client.post("/contributor/attestation");
    req = set_request::<(u64, String)>(
        req,
        &ctx.contributors[0].keypair,
        Some(&(2, String::from("https://namada.net"))),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::InternalServerError);
    assert!(response.body().is_some());

    // Try attestation with wrong participant
    req = client.post("/contributor/attestation");
    req = set_request::<(u64, String)>(
        req,
        &ctx.unknown_participant.keypair,
        Some(&(1, String::from("https://namada.net"))),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert!(response.body().is_some());

    // Ok attestation
    req = client.post("/contributor/attestation");
    req = set_request::<(u64, String)>(
        req,
        &ctx.contributors[0].keypair,
        Some(&(1, String::from("https://namada.net"))),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_none());

    // Try joining the queue with correct token
    req = client.post("/contributor/join_queue").remote(socket_address);
    req = set_request::<String>(
        req,
        &ctx.unknown_participant.keypair,
        Some(&format!(
            "9nFeNpukSn1eVwNc2vkfP8TAaw6DXNAgCNpxiQc437BxT3iF2xUMdo6wYQjqwxHwAZjVhQzdH3QMpJSbXvaDcnkVu6Ktt22AfYDypK2h72vuQK9fGNp"
        )),
    );
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_some());
}
