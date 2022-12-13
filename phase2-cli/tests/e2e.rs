//  NOTE: these tests must be run with --test-threads=1 due to the disk storage
//	being stored at the same path for all the test instances causing a conflict.
//	It could be possible to define a separate location (base_dir) for every test
//	but it's simpler to just run the tests sequentially.
//  NOTE: these tests require the phase1radix files to be placed in the phase2-cli folder

use std::{io::Write, net::IpAddr, sync::Arc};

use phase2_coordinator::{
    authentication::{KeyPair, Production, Signature},
    commands::{Computation, RandomSource},
    coordinator_state::CoordinatorState,
    environment::Testing,
    objects::{ContributionInfo, LockedLocators, TrimmedContributionInfo},
    rest,
    rest_utils::{self, PostChunkRequest, TOKENS_ZIP_FILE},
    storage::{ContributionLocator, ContributionSignatureLocator, Object},
    testing::coordinator,
    ContributionFileSignature, ContributionState, Coordinator, Participant,
};
use rocket::{
    catchers, routes,
    tokio::{
        self,
        sync::RwLock,
        task::JoinHandle,
        time::{self, Duration},
    },
    Error, Ignite, Rocket,
};

use async_stream::try_stream;
use futures_util::StreamExt;
use toml::Value;

use phase2_cli::requests;
use reqwest::{Client, Url};
use zip::write::FileOptions;

const ROUND_HEIGHT: u64 = 1;

struct TestParticipant {
    _inner: Participant,
    _address: IpAddr,
    keypair: KeyPair,
    locked_locators: Option<LockedLocators>,
}

struct TestCtx {
    contributors: Vec<TestParticipant>,
    unknown_participant: TestParticipant,
    coordinator: TestParticipant,
    coordinator_url: String,
    // Keep TempDir in scope for some tests
    _tokens_tmp_dir: tempfile::TempDir,
}

/// Launch the rocket server for testing with the proper configuration as a separate async Task.
async fn test_prelude() -> (TestCtx, JoinHandle<Result<Rocket<Ignite>, Error>>) {
    std::env::set_var("TOKEN_BLACKLIST", "true");
    // NOTE: never set NAMADA_MPC_IP_BAN here because we cannot test the IPs here (cannot mock them)

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
    std::env::set_var("TOKENS_FILE_PREFIX", "namada_tokens_cohort");

    // Instantiate the coordinator
    let mut coordinator = Coordinator::new(environment, Arc::new(Production)).unwrap();

    let keypair1 = KeyPair::new();
    let keypair2 = KeyPair::new();
    let keypair3 = KeyPair::new();

    let contributor1 = Participant::new_contributor(keypair1.pubkey().as_ref());
    let contributor2 = Participant::new_contributor(keypair2.pubkey().as_ref());
    let unknown_contributor = Participant::new_contributor(keypair3.pubkey().as_ref());

    let contributor1_ip = IpAddr::V4("0.0.0.1".parse().unwrap());
    let contributor2_ip = IpAddr::V4("0.0.0.2".parse().unwrap());
    let unknown_contributor_ip = IpAddr::V4("0.0.0.3".parse().unwrap());

    coordinator.initialize().unwrap();
    let coordinator_keypair = KeyPair::custom_new(
        coordinator.environment().default_verifier_signing_key(),
        coordinator.environment().coordinator_verifiers()[0].address(),
    );

    // Parse config toml file
    let config = tokio::fs::read_to_string("../Rocket.toml")
        .await
        .unwrap()
        .parse::<Value>()
        .unwrap();
    let default = config.get("default").unwrap();
    let coordinator_ip = IpAddr::V4(default.get("address").unwrap().as_str().unwrap().parse().unwrap());
    let coordinator_url = format!("http://{}:{}", coordinator_ip, default.get("port").unwrap());

    let coord_verifier = TestParticipant {
        _inner: coordinator.environment().coordinator_verifiers()[0].clone(),
        _address: coordinator_ip,
        keypair: coordinator_keypair,
        locked_locators: None,
    };

    coordinator
        .add_to_queue(
            contributor1.clone(),
            Some(contributor1_ip),
            String::from("9nFeNpukSn1eVwNc2vkfP7rdLh2njm5ewmCGxSLTW3GYmKP51fKjbRUvHDmntjEaQiq7iFux9tumgWEWVHwHQCs31oitpqBpMWpMydo1DnuFyLpsD6C"),
            10,
        )
        .unwrap();
    coordinator.update().unwrap();

    let (_, locked_locators) = coordinator.try_lock(&contributor1).unwrap();

    let coordinator: Arc<RwLock<Coordinator>> = Arc::new(RwLock::new(coordinator));

    let build = rocket::build()
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

    let ignite = build.ignite().await.unwrap();
    let handle = tokio::spawn(ignite.launch());

    let test_participant1 = TestParticipant {
        _inner: contributor1,
        _address: contributor1_ip,
        keypair: keypair1,
        locked_locators: Some(locked_locators),
    };
    let test_participant2 = TestParticipant {
        _inner: contributor2,
        _address: contributor2_ip,
        keypair: keypair2,
        locked_locators: None,
    };
    let unknown_participant = TestParticipant {
        _inner: unknown_contributor,
        _address: unknown_contributor_ip,
        keypair: keypair3,
        locked_locators: None,
    };

    let ctx = TestCtx {
        contributors: vec![test_participant1, test_participant2],
        unknown_participant,
        coordinator: coord_verifier,
        coordinator_url,
        _tokens_tmp_dir: tmp_dir,
    };

    (ctx, handle)
}

#[tokio::test]
async fn stop_coordinator() {
    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_secs(1)).await;

    // Wrong, request from non-coordinator participant
    let url = Url::parse(&ctx.coordinator_url).unwrap();
    let response = requests::get_stop_coordinator(&client, &url, &ctx.contributors[0].keypair).await;
    assert!(response.is_err());

    // Shut the server down
    let response = requests::get_stop_coordinator(&client, &url, &ctx.coordinator.keypair).await;
    assert!(response.is_ok());

    // Try sending another request (server should be unreachable)
    let response = requests::get_stop_coordinator(&client, &url, &ctx.coordinator.keypair).await;

    match response {
        Ok(_) => panic!("Expected error"),
        Err(e) => match e {
            requests::RequestError::Server(_) => panic!("Expected client-side error"),
            _ => (),
        },
    }

    // Drop the server
    handle.abort()
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

#[tokio::test]
async fn update_cohorts() {
    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_secs(1)).await;

    // Check tokens.zip file presence only when correct input
    // Remove tokens.zip file if present
    std::fs::remove_file(TOKENS_ZIP_FILE).ok();

    // Create new tokens zip file
    let new_invalid_tokens = get_serialized_tokens_zip(vec![
        "[\"9nFeNpukSn1eVwNc2vkfP7rdLh2njm5ewmCGxSLTW3GYmKP51fKjbRUvHDmntjEaQiq7iFux9tumgWEWVHwHQCs31oitpqBpMWpMydo1DnuFyLpsD6C\", \"9nFeNpukSn1eVwNc2vkfP7sQsLG3oS7623phb2Zzc23GAdXjuby4XAbwbWbx1uNaYrZorVLio4ZSt3u95sgi4fsS8hiZ3XkEttBF6q4461dGpoWv7ek\"]",
    ]);

    // Wrong, request from non-coordinator participant
    let url = Url::parse(&ctx.coordinator_url).unwrap();
    let response =
        requests::post_update_cohorts(&client, &url, &ctx.contributors[0].keypair, &new_invalid_tokens).await;
    assert!(response.is_err());
    assert!(std::fs::metadata(TOKENS_ZIP_FILE).is_err());

    // Wrong new tokens
    let response = requests::post_update_cohorts(&client, &url, &ctx.coordinator.keypair, &new_invalid_tokens).await;
    assert!(response.is_err());
    assert!(std::fs::metadata(TOKENS_ZIP_FILE).is_err());

    // Valid new tokens
    let new_valid_tokens = get_serialized_tokens_zip(vec![
        "[\"9nFeNpukSn1eVwNc2vkfP7rdLh2njm5ewmCGxSLTW3GYmKP51fKjbRUvHDmntjEaQiq7iFux9tumgWEWVHwHQCs31oitpqBpMWpMydo1DnuFyLpsD6C\", \"9nFeNpukSn1eVwNc2vkfP7sQsLG3oS7623phb2Zzc23GAdXjuby4XAbwbWbx1uNaYrZorVLio4ZSt3u95sgi4fsS8hiZ3XkEttBF6q4461dGpoWv7ek\", \"9nFeNpukSn1eVwNc2vkfP8SP4HrxTh9F86CY5pNWw8RF3jZa91q2i3yvE7ugpn9w2RzoZBZrdskgckmvJuVKq6ZWxfV8TepZYFd9SeARGHexi7tGGV2\"]",
        "[\"9nFeNpukSn1eVwNc2vkfP8TAaw6DXNAgCNpxiQc437BxT3iF2xUMdo6wYQjqwxHwAZjVhQzdH3QMpJSbXvaDcnkVu6Ktt22AfYDypK2h72vuQK9fGNp\"]",
    ]);

    let response = requests::post_update_cohorts(&client, &url, &ctx.coordinator.keypair, &new_valid_tokens).await;
    assert!(response.is_ok());
    assert!(std::fs::metadata(TOKENS_ZIP_FILE).is_ok());

    // Drop the server
    handle.abort()
}

#[tokio::test]
async fn get_status() {
    let access_token = "test-access_token";
    std::env::set_var("ACCESS_SECRET", access_token);
    // Spawn the server and get the test context
    let (ctx, handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_secs(1)).await;

    // Retrieve coordinator.json file with valid token
    let url = Url::parse(&ctx.coordinator_url).unwrap();
    let response = requests::get_coordinator_state(&url, access_token).await;
    assert!(response.is_ok());

    // Check deserialization
    let status: CoordinatorState = serde_json::from_slice(&response.unwrap()).unwrap();

    // Check Json deserialization of CoordinatorState (RuntimeState must be empty)
    assert_eq!(status.get_tokens()[0].len(), 3);
    assert!(status.get_tokens()[0].contains("9nFeNpukSn1eVwNc2vkfP7rdLh2njm5ewmCGxSLTW3GYmKP51fKjbRUvHDmntjEaQiq7iFux9tumgWEWVHwHQCs31oitpqBpMWpMydo1DnuFyLpsD6C"));
    assert!(status.get_tokens()[0].contains("9nFeNpukSn1eVwNc2vkfP7sQsLG3oS7623phb2Zzc23GAdXjuby4XAbwbWbx1uNaYrZorVLio4ZSt3u95sgi4fsS8hiZ3XkEttBF6q4461dGpoWv7ek"));
    assert!(status.get_tokens()[0].contains("9nFeNpukSn1eVwNc2vkfP8SP4HrxTh9F86CY5pNWw8RF3jZa91q2i3yvE7ugpn9w2RzoZBZrdskgckmvJuVKq6ZWxfV8TepZYFd9SeARGHexi7tGGV2"));
    assert!(status.get_current_ips().is_empty());
    assert!(status.get_current_tokens().is_empty());

    // Provide invalid token
    let response = requests::get_coordinator_state(&url, "wrong token").await;
    assert!(response.is_err());

    // Drop the server
    handle.abort()
}

#[tokio::test]
async fn get_contributor_queue_status() {
    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_secs(1)).await;

    // Non-existing contributor key
    let url = Url::parse(&ctx.coordinator_url).unwrap();
    let response = requests::get_contributor_queue_status(&client, &url, &ctx.unknown_participant.keypair).await;
    match response.unwrap() {
        rest_utils::ContributorStatus::Other => (),
        _ => panic!("Wrong ContributorStatus"),
    }

    // Ok
    let response = requests::get_contributor_queue_status(&client, &url, &ctx.contributors[0].keypair).await;
    match response.unwrap() {
        rest_utils::ContributorStatus::Round => (),
        _ => panic!("Wrong ContributorStatus"),
    }

    // Drop the server
    handle.abort()
}

#[tokio::test]
async fn heartbeat() {
    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_secs(1)).await;

    // Non-existing contributor key
    let url = Url::parse(&ctx.coordinator_url).unwrap();
    let response = requests::post_heartbeat(&client, &url, &ctx.unknown_participant.keypair).await;
    assert!(response.is_err());

    // Ok
    requests::post_heartbeat(&client, &url, &ctx.contributors[0].keypair)
        .await
        .unwrap();

    // Drop the server
    handle.abort();
}

#[tokio::test]
async fn update_coordinator() {
    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_secs(1)).await;

    // Wrong, request from non-coordinator
    let url = Url::parse(&ctx.coordinator_url).unwrap();
    assert!(requests::get_update(&client, &url, &ctx.contributors[0].keypair)
        .await
        .is_err());

    // Ok
    requests::get_update(&client, &url, &ctx.coordinator.keypair)
        .await
        .unwrap();

    // Drop the server
    handle.abort()
}

#[tokio::test]
async fn wrong_post_attestation() {
    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, _handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_secs(1)).await;

    // Wrong, missing contribution
    let url = Url::parse(&ctx.coordinator_url).unwrap();
    assert!(requests::post_attestation(
        &client,
        &url,
        &ctx.contributors[0].keypair,
        &(1, String::from("https://namada.net"))
    )
    .await
    .is_err());
}

#[tokio::test]
async fn join_queue() {
    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_secs(1)).await;

    // Wrong request, invalid token
    let url = Url::parse(&ctx.coordinator_url).unwrap();
    let mut response = requests::post_join_queue(
        &client,
        &url,
        &ctx.unknown_participant.keypair,
        &String::from("9nFeNpukSn1eVwNc2vkfP7sQsLG3oS7623phb2Zzc23GAdXjuby4XAbwbWbx1uNaYrZorVLio4ZSt3u95sgi4fsS8hiZ3XkEttBF6q4461dGpoWv7er"),
    )
    .await;
    assert!(response.is_err());

    // Ok request
    requests::post_join_queue(
        &client,
        &url,
        &ctx.unknown_participant.keypair,
        &String::from("9nFeNpukSn1eVwNc2vkfP7sQsLG3oS7623phb2Zzc23GAdXjuby4XAbwbWbx1uNaYrZorVLio4ZSt3u95sgi4fsS8hiZ3XkEttBF6q4461dGpoWv7ek"),
    )
    .await
    .unwrap();

    // Wrong request, token already in use
    response = requests::post_join_queue(
        &client,
        &url,
        &ctx.contributors[1].keypair,
        &String::from("9nFeNpukSn1eVwNc2vkfP7sQsLG3oS7623phb2Zzc23GAdXjuby4XAbwbWbx1uNaYrZorVLio4ZSt3u95sgi4fsS8hiZ3XkEttBF6q4461dGpoWv7ek"),
    )
    .await;
    assert!(response.is_err());

    // Wrong request, already existing contributor
    response = requests::post_join_queue(
        &client,
        &url,
        &ctx.unknown_participant.keypair,
        &String::from("9nFeNpukSn1eVwNc2vkfP8SP4HrxTh9F86CY5pNWw8RF3jZa91q2i3yvE7ugpn9w2RzoZBZrdskgckmvJuVKq6ZWxfV8TepZYFd9SeARGHexi7tGGV2"),
    )
    .await;
    assert!(response.is_err());

    // Drop the server
    handle.abort()
}

/// Test wrong usage of lock_chunk.
#[tokio::test]
async fn wrong_lock_chunk() {
    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, _) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_secs(1)).await;

    // Wrong request, unknown participant
    let url = Url::parse(&ctx.coordinator_url).unwrap();
    let response = requests::get_lock_chunk(&client, &url, &ctx.unknown_participant.keypair).await;
    assert!(response.is_err());
}

/// Test wrong usage of contribute_chunk.
#[tokio::test]
async fn wrong_contribute_chunk() {
    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_secs(1)).await;

    let c = ContributionLocator::new(ROUND_HEIGHT, 0, 1, false);
    let s = ContributionSignatureLocator::new(ROUND_HEIGHT, 0, 1, false);
    let r = PostChunkRequest::new(ROUND_HEIGHT, c, s);

    // Non-existing contributor key
    let url = Url::parse(&ctx.coordinator_url).unwrap();
    let response = requests::post_contribute_chunk(&client, &url, &ctx.unknown_participant.keypair, &r).await;
    assert!(response.is_err());

    // Non-current-contributor
    let response = requests::post_contribute_chunk(&client, &url, &ctx.contributors[1].keypair, &r).await;
    assert!(response.is_err());

    // Drop the server
    handle.abort()
}

#[tokio::test]
async fn wrong_verify() {
    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, _) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_secs(1)).await;

    // Wrong, request from non-coordinator participant
    let url = Url::parse(&ctx.coordinator_url).unwrap();
    let response = requests::get_verify_chunks(&client, &url, &ctx.contributors[0].keypair).await;
    assert!(response.is_err())
}

#[tokio::test]
async fn wrong_post_contribution_info() {
    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_secs(1)).await;

    let contrib_info = ContributionInfo::default();

    // Non-existing contributor key
    let url = Url::parse(&ctx.coordinator_url).unwrap();
    let response =
        requests::post_contribution_info(&client, &url, &ctx.unknown_participant.keypair, &contrib_info).await;
    assert!(response.is_err());

    // Non-current-contributor participant
    let response = requests::post_contribution_info(&client, &url, &ctx.contributors[1].keypair, &contrib_info).await;
    assert!(response.is_err());

    // Drop the server
    handle.abort()
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
/// - join_queue with already contributed token
/// - Skip to second cohort
/// - Try joinin queue with expired token
/// - Try attestation
/// - Try joinin queue with correct token
///
#[tokio::test]
async fn contribution() {
    use rand::Rng;
    use setup_utils::calculate_hash;

    const COHORT_TIME: u64 = 15;
    std::env::set_var("NAMADA_COHORT_TIME", COHORT_TIME.to_string()); // 15 seconds for each cohort

    let client = Client::new();
    // Spawn the server and get the test context
    let (ctx, handle) = test_prelude().await;
    // Wait for server startup
    time::sleep(Duration::from_secs(1)).await;
    let url = Url::parse(&ctx.coordinator_url).unwrap();
    let start_time = std::time::Instant::now();

    // Remove tokens.zip file if present
    std::fs::remove_file(TOKENS_ZIP_FILE).ok();

    // Get challenge url
    let challenge_url = requests::get_challenge_url(&client, &url, &ctx.contributors[0].keypair, &ROUND_HEIGHT)
        .await
        .unwrap();

    // Get challenge
    let mut challenge_stream = requests::get_challenge(&client, challenge_url.as_str()).await.unwrap();

    let mut challenge: Vec<u8> = Vec::new();
    while let Some(b) = challenge_stream.0.next().await {
        let b = b.unwrap();
        challenge.extend_from_slice(&b);
    }

    // Get contribution url
    let (chunk_url, sig_url) =
        requests::get_contribution_url(&client, &url, &ctx.contributors[0].keypair, &ROUND_HEIGHT)
            .await
            .unwrap();

    // Upload chunk
    let contribution_locator = ContributionLocator::new(ROUND_HEIGHT, 0, 1, false);

    let challenge_hash = calculate_hash(challenge.as_ref());

    let mut contribution: Vec<u8> = Vec::new();
    contribution.write_all(challenge_hash.as_slice()).unwrap();
    let seed = RandomSource::Seed(rand::thread_rng().gen::<[u8; 32]>());
    Computation::contribute(&challenge, &mut contribution, &seed).unwrap();

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

    let contribution_len = contribution.len() as u64;
    let mut stream = futures_util::stream::iter(contribution);

    let contrib_stream = try_stream! {
        while let Some(b) = stream.next().await {
            yield vec![b].into();
        }
    };
    requests::upload_chunk(
        &client,
        chunk_url.as_str(),
        sig_url.as_str(),
        contrib_stream,
        contribution_len,
        &contribution_file_signature,
    )
    .await
    .unwrap();

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

    requests::post_contribution_info(&client, &url, &ctx.contributors[0].keypair, &contrib_info)
        .await
        .unwrap();

    // Contribute
    let post_chunk = PostChunkRequest::new(ROUND_HEIGHT, contribution_locator, contribution_file_signature_locator);

    requests::post_contribute_chunk(&client, &url, &ctx.contributors[0].keypair, &post_chunk)
        .await
        .unwrap();

    // Verify chunk
    requests::get_verify_chunks(&client, &url, &ctx.coordinator.keypair)
        .await
        .unwrap();

    // Get contributions info
    let summary_bytes = requests::get_contributions_info(&url).await.unwrap();
    let summary: Vec<TrimmedContributionInfo> = serde_json::from_slice(&summary_bytes).unwrap();
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
    let response = requests::post_update_cohorts(&client, &url, &ctx.coordinator.keypair, &new_valid_tokens).await;
    assert!(response.is_ok());
    assert!(std::fs::metadata(TOKENS_ZIP_FILE).is_ok());

    // Join queue with already contributed Token
    let response = requests::post_join_queue(
        &client,
        &url,
        &ctx.unknown_participant.keypair,
        &String::from("9nFeNpukSn1eVwNc2vkfP7rdLh2njm5ewmCGxSLTW3GYmKP51fKjbRUvHDmntjEaQiq7iFux9tumgWEWVHwHQCs31oitpqBpMWpMydo1DnuFyLpsD6C"),
    )
    .await;
    assert!(response.is_err());

    // Skip to second cohort and try joining the queue with expired token
    let sleep_time = COHORT_TIME - start_time.elapsed().as_secs();
    tokio::time::sleep(std::time::Duration::from_secs(sleep_time)).await;

    let response = requests::post_join_queue(
        &client,
        &url,
        &ctx.contributors[1].keypair,
        &String::from("9nFeNpukSn1eVwNc2vkfP7rdLh2njm5ewmCGxSLTW3GYmKP51fKjbRUvHDmntjEaQiq7iFux9tumgWEWVHwHQCs31oitpqBpMWpMydo1DnuFyLpsD6C"),
    )
    .await;
    assert!(response.is_err());

    // Attestation

    // Wrong url format
    let response = requests::post_attestation(
        &client,
        &url,
        &ctx.contributors[0].keypair,
        &(1, String::from("not_a_valid_url")),
    )
    .await;
    assert!(response.is_err());

    // Wrong round height
    let response = requests::post_attestation(
        &client,
        &url,
        &ctx.contributors[0].keypair,
        &(2, String::from("https://namada.net")),
    )
    .await;
    assert!(response.is_err());

    // Try attestation with wrong participant
    let response = requests::post_attestation(
        &client,
        &url,
        &ctx.unknown_participant.keypair,
        &(1, String::from("https://namada.net")),
    )
    .await;
    assert!(response.is_err());

    // Ok attestation
    requests::post_attestation(
        &client,
        &url,
        &ctx.contributors[0].keypair,
        &(1, String::from("https://namada.net")),
    )
    .await
    .unwrap();

    // Try joining the queue with correct token
    requests::post_join_queue(
        &client,
        &url,
        &ctx.unknown_participant.keypair,
        &String::from("9nFeNpukSn1eVwNc2vkfP8TAaw6DXNAgCNpxiQc437BxT3iF2xUMdo6wYQjqwxHwAZjVhQzdH3QMpJSbXvaDcnkVu6Ktt22AfYDypK2h72vuQK9fGNp"),
    )
    .await
    .unwrap();

    // Drop the server
    handle.abort()
}
