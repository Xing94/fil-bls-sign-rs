#![cfg_attr(
not(test),
deny(
clippy::option_unwrap_used,
clippy::option_expect_used,
clippy::result_unwrap_used,
clippy::result_expect_used,
)
)]

pub mod bls;
pub mod android;