use crate::authentication::{KeyPair, Production, Signature};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContributionInfoError {
    #[error("Keypair doesn't match the pubkey")]
    InvalidSigKey,
    #[error("Error while serializing ContributionInfo: {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("Error while signing ContributionInfo: {0}")]
    SignatureError(String),
    #[error("Expected ContributionInfo to be serialized as a Map")]
    UnexpectedSerializationFormat,
}

/// Timestamps of the contribution
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ContributionTimeStamps {
    // User starts the CLI
    pub start_contribution: DateTime<Utc>,
    // User has joined the queue
    pub joined_queue: DateTime<Utc>,
    // User has locked the challenge on the coordinator
    pub challenge_locked: DateTime<Utc>,
    // User has completed the download of the challenge
    pub challenge_downloaded: DateTime<Utc>,
    // User starts computation locally or downloads the file to another machine
    pub start_computation: DateTime<Utc>,
    // User finishes computation locally or uploads the file from another machine
    pub end_computation: DateTime<Utc>,
    // User attests that the file was uploaded correctly
    pub end_contribution: DateTime<Utc>,
}

impl Default for ContributionTimeStamps {
    /// Generate a [`ContributionTimeStamps`] instance with all the timestamps
    /// set to [`Utc::now`].
    fn default() -> Self {
        let timestamp = Utc::now();
        Self {
            start_contribution: timestamp,
            joined_queue: timestamp,
            challenge_locked: timestamp,
            challenge_downloaded: timestamp,
            start_computation: timestamp,
            end_computation: timestamp,
            end_contribution: timestamp,
        }
    }
}

/// A summarized version of [`ContributionTimeStamps`]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrimmedContributionTimeStamps {
    start_contribution: DateTime<Utc>,
    end_contribution: DateTime<Utc>,
}

impl From<ContributionTimeStamps> for TrimmedContributionTimeStamps {
    fn from(parent: ContributionTimeStamps) -> Self {
        Self {
            start_contribution: parent.start_contribution,
            end_contribution: parent.end_contribution,
        }
    }
}

/// Summary info about the contribution
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ContributionInfo {
    // Name of the contributor
    pub full_name: Option<String>,
    // Email of the contributor
    pub email: Option<String>,
    // ed25519 public key, hex encoded
    pub public_key: String,
    // User can choose to contribute on another machine
    pub is_another_machine: bool,
    // User can choose the default method to generate randomness or his own.
    pub is_own_seed_of_randomness: bool,
    // Cohort in which the participant joined the queue
    pub joined_cohort: u64,
    // Round in which the contribution took place
    pub ceremony_round: u64,
    // Hash of the contribution run by masp-mpc, contained in the transcript
    pub contribution_hash: String,
    // Signature of the contribution hash
    pub contribution_hash_signature: String,
    /// Url providing an attestation of the contribution
    pub attestation: Option<String>,
    // Some timestamps to get performance metrics of the ceremony
    pub timestamps: ContributionTimeStamps,
    // Signature of this struct, computed on the json string encoding of all the other fields of this struct
    pub contributor_info_signature: String,
}

impl ContributionInfo {
    /// Calculates the hash of the json string encoding all the fields of the struct
    /// expect for the signature itself.
    fn hash_for_signature(&self) -> Result<String, ContributionInfoError> {
        let mut serde_contrib_info = serde_json::to_value(self.clone())?;

        // Remove contributor_info_signature from json
        let map = serde_contrib_info
            .as_object_mut()
            .ok_or(ContributionInfoError::UnexpectedSerializationFormat)?;
        map.remove("contributor_info_signature");
        let serialized_contrib_info = serde_contrib_info.to_string();

        // Compute digest
        let mut hasher = Sha256::new();
        hasher.update(serialized_contrib_info);

        Ok(format!("{:x?}", hasher.finalize()))
    }

    /// Computes the signature of a json string encoding the struct.
    pub fn try_sign(&mut self, keypair: &KeyPair) -> Result<(), ContributionInfoError> {
        let digest = self.hash_for_signature()?;

        // Compute signature
        if keypair.pubkey() != self.public_key {
            // Keypair must match the pubkey of self
            return Err(ContributionInfoError::InvalidSigKey);
        }

        let contrib_info_signature = Production
            .sign(keypair.sigkey(), digest.as_str())
            .map_err(|e| ContributionInfoError::SignatureError(format!("{}", e)))?;
        self.contributor_info_signature = contrib_info_signature;

        Ok(())
    }

    /// Verifies the signature.
    #[cfg(test)]
    fn verify_signature(&self) -> Result<bool, ContributionInfoError> {
        let serialized_contrib_info = self.hash_for_signature()?;

        Ok(Production.verify(
            self.public_key.as_str(),
            serialized_contrib_info.as_str(),
            self.contributor_info_signature.as_str(),
        ))
    }
}

/// A summarized version of [`ContributionInfo`]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrimmedContributionInfo {
    full_name: Option<String>,
    public_key: String,
    is_another_machine: bool,
    is_own_seed_of_randomness: bool,
    joined_cohort: u64,
    ceremony_round: u64,
    contribution_hash: String,
    contribution_hash_signature: String,
    attestation: Option<String>,
    timestamps: TrimmedContributionTimeStamps,
}

impl From<ContributionInfo> for TrimmedContributionInfo {
    fn from(parent: ContributionInfo) -> Self {
        Self {
            full_name: parent.full_name,
            public_key: parent.public_key,
            is_another_machine: parent.is_another_machine,
            is_own_seed_of_randomness: parent.is_own_seed_of_randomness,
            joined_cohort: parent.joined_cohort,
            ceremony_round: parent.ceremony_round,
            contribution_hash: parent.contribution_hash,
            contribution_hash_signature: parent.contribution_hash_signature,
            attestation: parent.attestation,
            timestamps: parent.timestamps.into(),
        }
    }
}

impl TrimmedContributionInfo {
    pub fn public_key(&self) -> &str {
        self.public_key.as_ref()
    }

    pub fn ceremony_round(&self) -> u64 {
        self.ceremony_round
    }

    #[cfg(debug_assertions)]
    pub fn is_another_machine(&self) -> bool {
        self.is_another_machine
    }

    #[cfg(debug_assertions)]
    pub fn is_own_seed_of_randomness(&self) -> bool {
        self.is_own_seed_of_randomness
    }
}

#[cfg(test)]
mod tests {
    use crate::authentication::KeyPair;

    use super::ContributionInfo;

    #[test]
    fn sign_and_verify() {
        // Test default
        let keypair = KeyPair::new();
        let mut test_info = ContributionInfo::default();
        test_info.public_key = keypair.pubkey().to_owned();

        test_info.try_sign(&keypair).unwrap();
        assert!(test_info.verify_signature().unwrap());

        // Test custom
        test_info.full_name = Some(String::from("Test Name"));
        test_info.email = Some(String::from("test_name@test.dev"));
        test_info.ceremony_round = 12;
        test_info.contribution_hash = String::from("Not a valid hash");
        test_info.contribution_hash_signature = String::from("Not a valid signature");
        test_info.contribution_hash = String::from("Not a valid file hash");
        test_info.contribution_hash_signature = String::from("Not a valid file signature");

        test_info.try_sign(&keypair).unwrap();
        assert!(test_info.verify_signature().unwrap());
    }
}
