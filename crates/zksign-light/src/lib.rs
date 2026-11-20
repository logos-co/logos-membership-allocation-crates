#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "verify")]
pub mod verify;

pub use auth_vector::hex::{hex32_bytes, norm_hex32, strip_0x};
#[cfg(feature = "client")]
pub use client::{parse_sig_reply, pow_status, sign_zk, HttpZkNode, ZkNode, SIGN_MIN_TIMEOUT_MS};
#[cfg(feature = "verify")]
pub use verify::{
    default_vk, is_canonical_fr, verify_sig, vk_from_config, vk_from_path_cached, zero_pk,
    zero_pk_le, PreparedVk, VkSource, DEFAULT_VK_JSON,
};
