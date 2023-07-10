use crate::rand::GetRandomFailed;
use crate::server::ProducesTickets;
use crate::suites;
use crate::{Error, NamedGroup};

use std::fmt::Debug;

/// *ring* based CryptoProvider.
#[cfg(feature = "defaultprovider")]
pub mod ring;

/// TLS message encryption/decryption intefaces.
pub mod cipher;

/// Hashing interfaces.
pub mod hash;

/// HMAC interfaces.
pub mod hmac;

/// Pluggable crypto galore.
pub trait CryptoProvider: Send + Sync + 'static {
    /// KeyExchange operations that are supported by the provider.
    type KeyExchange: KeyExchange;

    /// Build a ticket generator.
    fn ticket_generator() -> Result<Box<dyn ProducesTickets>, GetRandomFailed>;

    /// Fill the given buffer with random bytes.
    fn fill_random(buf: &mut [u8]) -> Result<(), GetRandomFailed>;

    /// Configure a safe set of cipher suites that can be used as the defaults.
    fn default_cipher_suites() -> &'static [suites::SupportedCipherSuite];
}

/// An in-progress key exchange over a [SupportedGroup].
pub trait KeyExchange: Sized + Send + Sync + 'static {
    /// The supported group the key exchange is operating over.
    type SupportedGroup: SupportedGroup;

    /// Start a key exchange using the [NamedGroup] if it is a suitable choice
    /// based on the groups supported.
    ///
    /// # Errors
    ///
    /// Returns an error if the [NamedGroup] is not supported, or if a key exchange
    /// can't be started (see [KeyExchange#start]).
    fn choose(
        name: NamedGroup,
        supported: &[&'static Self::SupportedGroup],
    ) -> Result<Self, KeyExchangeError>;

    /// Start a key exchange using the [SupportedGroup]. This will prepare an ephemeral
    /// secret key in the supported group, and a corresponding public key. The key exchange
    /// must be completed by calling [KeyExchange#complete].
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    fn start(skxg: &'static Self::SupportedGroup) -> Result<Self, GetRandomFailed>;

    /// Completes the key exchange, given the peer's public key.
    ///
    /// The shared secret is passed into the closure passed down in `f`, and the result of calling
    /// `f` is returned to the caller.
    fn complete<T>(self, peer: &[u8], f: impl FnOnce(&[u8]) -> Result<T, ()>) -> Result<T, Error>;

    /// Return the group being used.
    fn group(&self) -> NamedGroup;

    /// Return the public key being used.
    fn pub_key(&self) -> &[u8];

    /// Return all supported key exchange groups.
    fn all_kx_groups() -> &'static [&'static Self::SupportedGroup];
}

/// Enumerates possible key exchange errors.
pub enum KeyExchangeError {
    /// Returned when the specified group is unsupported.
    UnsupportedGroup,

    /// Returned when key exchange fails.
    KeyExchangeFailed(GetRandomFailed),
}

/// A trait describing a supported key exchange group that can be identified by name.
pub trait SupportedGroup: Debug + Send + Sync + 'static {
    /// Named group the SupportedGroup operates in.
    fn name(&self) -> NamedGroup;
}

// Due to trait coherence, providers can't supply `WantsVerifier` builder states.
// So we provide trivial ones here. TODO: could do better given this is generic over CryptoProvider.
#[cfg(not(feature = "defaultprovider"))]
use crate::{
    builder::{ConfigBuilder, WantsVerifier},
    verify, versions, ClientConfig,
};
#[cfg(not(feature = "defaultprovider"))]
use std::sync::Arc;

#[cfg(not(feature = "defaultprovider"))]
impl<C: CryptoProvider> ConfigBuilder<ClientConfig<C>, WantsVerifier<C>> {
    /// Set a custom certificate verifier.
    pub fn with_custom_certificate_verifier(
        self,
        verifier: Arc<dyn verify::ServerCertVerifier>,
    ) -> ConfigBuilder<ClientConfig<C>, WantsClientCert<C>> {
        ConfigBuilder {
            state: WantsClientCert {
                cipher_suites: self.state.cipher_suites,
                kx_groups: self.state.kx_groups,
                versions: self.state.versions,
                verifier,
            },
            side: std::marker::PhantomData::default(),
        }
    }
}

#[cfg(not(feature = "defaultprovider"))]
/// A config builder state where the caller needs to supply whether and how to provide a client
/// certificate.
///
/// For more information, see the [`ConfigBuilder`] documentation.
pub struct WantsClientCert<C: CryptoProvider> {
    cipher_suites: Vec<suites::SupportedCipherSuite>,
    kx_groups: Vec<&'static <<C as CryptoProvider>::KeyExchange as KeyExchange>::SupportedGroup>,
    versions: versions::EnabledVersions,
    verifier: Arc<dyn verify::ServerCertVerifier>,
}

#[cfg(not(feature = "defaultprovider"))]
impl<C: CryptoProvider> ConfigBuilder<ClientConfig<C>, WantsClientCert<C>> {
    /// Do not support client auth.
    pub fn with_no_client_auth(self) -> ClientConfig<C> {
        self.with_client_cert_resolver(Arc::new(crate::client::handy::FailResolveClientCert {}))
    }

    /// Sets a custom [`ResolvesClientCert`].
    pub fn with_client_cert_resolver(
        self,
        client_auth_cert_resolver: Arc<dyn crate::client::ResolvesClientCert>,
    ) -> ClientConfig<C> {
        ClientConfig {
            cipher_suites: self.state.cipher_suites,
            kx_groups: self.state.kx_groups,
            alpn_protocols: Vec::new(),
            resumption: crate::client::Resumption::default(),
            max_fragment_size: None,
            client_auth_cert_resolver,
            versions: self.state.versions,
            enable_sni: true,
            verifier: self.state.verifier,
            key_log: Arc::new(crate::key_log::NoKeyLog {}),
            #[cfg(feature = "secret_extraction")]
            enable_secret_extraction: false,
            enable_early_data: false,
            provider: std::marker::PhantomData,
        }
    }
}
