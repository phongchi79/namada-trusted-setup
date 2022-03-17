#[macro_use]
extern crate rocket;
use rand::RngCore;
use rocket::serde::{json::Json, Deserialize};
use rocket::{State};

const SEED_LENGTH: usize = 32;
type Seed = [u8; SEED_LENGTH];

use phase1_coordinator::{
	authentication::{Dummy, Signature},
	environment::{Development, Environment, Parameters, Settings},
	Coordinator, Participant,
};

use phase1::{helpers::CurveKind, ContributionMode, ProvingSystem};

type SigningKey = String;
use std::{net::IpAddr, sync::Arc};
use tracing_subscriber;

use tokio::sync::RwLock;

#[derive(Deserialize)]
pub struct ConfirmationKey {
	address: String,
	private_key: String,
}

#[get("/")]
fn index(remote_ip: IpAddr) -> String {
	format!("Hello my dear! {}", remote_ip)
}

fn create_contributor(id: &str) -> (Participant, SigningKey, Seed) {
	let contributor = Participant::Contributor(format!("test-contributor-{}", id));
	let contributor_signing_key: SigningKey = "secret_key".to_string();

	let mut seed: Seed = [0; SEED_LENGTH];
	rand::thread_rng().fill_bytes(&mut seed[..]);

	(contributor, contributor_signing_key, seed)
}

// TODO: authorize client with its private/public key pair
// TOOD: 1. POST `/contributor/join_queue/`
#[post("/contributor/join_queue", data = "<contributor_public_key_data>")]
async fn join_queue(
	coordinator: &State<Arc<RwLock<Coordinator>>>,
	contributor_public_key_data: Json<String>,
	contributor_ip: IpAddr,
) -> Json<bool> {
	let contributor_public_key: &str = &contributor_public_key_data.into_inner();
	let contributor = Participant::new_contributor(contributor_public_key);

	coordinator
		.write()
		.await
		.add_to_queue(contributor, Some(contributor_ip), 10)
		.unwrap();

	Json(true)
}

// TODO: 2. POST `/contributor/lock_chunk/`
async fn lock_chunk(coordinator: &State<Arc<RwLock<Coordinator>>>) -> () {
	//
	let (contributor1, contributor_signing_key1, seed1) = create_contributor("1");
	coordinator.write().await.try_lock(&contributor1);
}

// TODO: 3. GET `/download/challenge/{chunk_id}/{contribution_id}/`
// TODO: 4. Contributors are processing the chunk
// TOOD: 5. POST `/upload/challenge/{chunk_id}/{contribution_id}/`
// TODO: 6. POST `/contributor/contribute_chunk/`

// TODO: * POST `/contributor/heartbeat/`
// TODO: * GET `/contributor/get_tasks_left/`
// TODO: * POST `/v1/contributor/status`

#[get("/update")]
async fn update_coordinator(coordinator: &State<Arc<RwLock<Coordinator>>>) -> () {
	if let Err(error) = coordinator.write().await.update() {
		error!("{}", error);
	}
}

fn instantiate_coordinator(environment: &Environment, signature: Arc<dyn Signature>) -> anyhow::Result<Coordinator> {
	Ok(Coordinator::new(environment.clone(), signature)?)
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
	tracing_subscriber::fmt::init();
	// Set the environment.

	// let environment: Environment = Development::from(Parameters::TestCustom {
	// 	number_of_chunks: 8,
	// 	power: 12,
	// 	batch_size: 256,
	// })
	// .into();

	// let environment: Production = Default::default();

	// This parameters are to be exposed publicly to the REST API
	let parameters = Parameters::Custom(Settings::new(
		ContributionMode::Full,
		ProvingSystem::Groth16,
		CurveKind::Bls12_377,
		6,  /* power */
		16, /* batch_size */
		16, /* chunk_size */
	));

	let environment: Development = Development::from(parameters);

	// Instantiate the coordinator.
	let coordinator: Arc<RwLock<Coordinator>> = Arc::new(RwLock::new(
		instantiate_coordinator(&environment, Arc::new(Dummy)).unwrap(),
	));

	let ceremony_coordinator = coordinator.clone();

	// Initialize the coordinator.
	ceremony_coordinator.write().await.initialize().unwrap();

	let rocket = rocket::build()
		.mount("/", routes![index, update_coordinator, join_queue])
		.manage(ceremony_coordinator)
		.ignite()
		.await?;
	println!("Hello, Rocket: {:?}", rocket);

	let result = rocket.launch().await;
	println!("The server shutdown: {:?}", result);

	result
}
