pub mod append;
pub mod archive;
pub mod fixtures;
pub mod keys;
#[cfg(feature = "ro-crate")]
pub mod ro_crate;
pub mod writer;

pub mod util {
    #[allow(unused_imports)]
    // Targets import different subsets through this compatibility facade.
    pub use super::archive::open;
    #[allow(unused_imports)]
    // Targets import different subsets through this compatibility facade.
    pub use super::fixtures::fixture;
    #[allow(unused_imports)]
    // Targets import different subsets through this compatibility facade.
    pub use super::keys::{private_key, public_key};
}
