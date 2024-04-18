//! Generic ticket with expiration and signed with Ed25519 algorithm.
//!
//! Tickets are special kind of tokens with a structure to JWT. A ticket is
//! a string formed by two parts separated by a point `.`:
//! - the first part is the payload, a base64 url encoded json, only the field
//!   `exp` is implicitly deinfed by the ticket, it contains the expiration of
//!   the ticket represented using unix timestamp in milliseconds;
//! - the second part is the signature of the decoded payload, the signature is
//!   computed using the Ed25519 algorithm.
//!
//! Each token is signed with an asymetric alorightm to allow the user to
//! verify the authenticity of the ticket.

use base64ct::{Base64Url, Encoding};
use ed25519_dalek::{ed25519::signature::Signer, Signature, SigningKey};
use mello_core::{
    rng,
    time::{DateTime, Duration},
    MasterKey,
};
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Ticket with user defined data and expiration.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Ticket<T> {
    /// Ticket payload
    #[serde(flatten)]
    payload: T,
    /// The expiration of the ticket.
    #[serde(
        rename = "exp",
        serialize_with = "DateTime::serialize_with_unix_timestamp",
        deserialize_with = "DateTime::deserialize_with_unix_timestamp"
    )]
    expiration: DateTime,
}

impl<T> Ticket<T> {
    /// Create a new ticket with the given payload and lifetime.
    pub fn new(payload: T, lifetime: Duration) -> Self {
        let expiration = DateTime::now() + lifetime;
        Self {
            payload,
            expiration: expiration.round(Duration::MILLISECOND),
        }
    }

    /// Unwrap the payload if the ticket is not expired.
    pub fn unwrap(self) -> Option<T> {
        let is_not_expired = self.expiration > DateTime::now();
        is_not_expired.then_some(self.payload)
    }

    /// Encode the ticket using JSON serialization and base64 url.
    fn encode(&self) -> String
    where
        T: Serialize,
    {
        let json_ticket = serde_json::to_vec(self).expect("Failed to serialize Ticket");
        Base64Url::encode_string(&json_ticket)
    }

    /// Decode the ticket using base64 url and JSON deserialization.
    fn decode(input: &str) -> Result<Self, InvalidTicket>
    where
        T: DeserializeOwned,
    {
        let json_ticket = Base64Url::decode_vec(input).map_err(|_| InvalidTicket)?;
        serde_json::from_slice(&json_ticket).map_err(|_| InvalidTicket)
    }
}

/// The private key used to sign and verify tickets.
pub struct TicketKey(SigningKey);

impl TicketKey {
    /// The length of the secret key in bytes.
    const BYTES: usize = ed25519_dalek::SECRET_KEY_LENGTH;

    /// Derive a [`TicketKey`] from a [`MasterKey`].
    pub fn derive(key: &MasterKey, tag: &str) -> Self {
        let mut secret_key = [0u8; Self::BYTES];
        key.fill_bytes(tag, &mut secret_key);
        Self(SigningKey::from_bytes(&secret_key))
    }

    /// Generate a new random key.
    pub fn generate() -> Self {
        let mut secret_key = [0u8; Self::BYTES];
        rng::with_crypto_rng(|rng| rng.fill_bytes(&mut secret_key));
        Self(SigningKey::from_bytes(&secret_key))
    }

    /// Sign the [`Ticket`] with the given [`TicketKey`] to generate a new code.
    pub fn sign<T>(&self, ticket: &Ticket<T>) -> String
    where
        T: Serialize,
    {
        let ticket = ticket.encode();
        let signature = {
            let signature = self.0.sign(ticket.as_bytes());
            Base64Url::encode_string(signature.to_bytes().as_slice())
        };

        format!("{ticket}.{signature}")
    }

    /// Verify the code using the given [`TicketKey`] to extract the [`Ticket`].
    pub fn verify<T>(&self, code: &str) -> Result<Ticket<T>, InvalidTicket>
    where
        T: DeserializeOwned,
    {
        let (ticket, signature) = code.split_once('.').ok_or(InvalidTicket)?;

        let signature = Base64Url::decode_vec(signature).map_err(|_| InvalidTicket)?;
        let signature = Signature::from_slice(&signature).map_err(|_| InvalidTicket)?;
        self.0
            .verify(ticket.as_bytes(), &signature)
            .map_err(|_| InvalidTicket)?;

        Ticket::decode(ticket)
    }
}

/// Error type for when a ticket is not valid (for different reasons).
#[derive(Clone, Copy, Debug)]
pub struct InvalidTicket;

#[cfg(test)]
mod test {
    use claym::*;

    use mello_core::time::MockDateTime;

    use super::*;

    #[test]
    fn unwrap_not_expired_ticket() {
        MockDateTime::freeze();
        let ticket = Ticket::new((), Duration::hours(1));
        assert_some!(ticket.unwrap());
    }

    #[test]
    fn unwrap_expired_ticket() {
        MockDateTime::freeze();
        let ticket = Ticket::new((), Duration::hours(1));
        MockDateTime::advance(Duration::minutes(61));
        assert_none!(ticket.unwrap());
    }

    #[test]
    fn check_if_serialization_works() {
        let ticket = Ticket::new((), Duration::hours(1));
        let serialized_ticket = assert_ok!(serde_json::to_string(&ticket));
        let deserialized_ticket = assert_ok!(serde_json::from_str(&serialized_ticket));
        assert_eq!(ticket, deserialized_ticket);
    }
}
