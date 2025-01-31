use crate::bls::api::{fil_BLSDigest, fil_BLSPrivateKey, fil_BLSPublicKey, fil_BLSSignature};

/// HashResponse

#[repr(C)]
pub struct fil_HashResponse {
    pub digest: fil_BLSDigest,
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_hash_response(ptr: *mut fil_HashResponse) {
    let _ = Box::from_raw(ptr);
}

/// AggregateResponse

#[repr(C)]
pub struct fil_AggregateResponse {
    pub signature: fil_BLSSignature,
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_aggregate_response(ptr: *mut fil_AggregateResponse) {
    let _ = Box::from_raw(ptr);
}

/// PrivateKeyGenerateResponse

#[repr(C)]
pub struct fil_PrivateKeyGenerateResponse {
    pub private_key: fil_BLSPrivateKey,
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_private_key_generate_response(
    ptr: *mut fil_PrivateKeyGenerateResponse,
) {
    let _ = Box::from_raw(ptr);
}

/// PrivateKeySignResponse

#[repr(C)]
pub struct fil_PrivateKeySignResponse {
    pub signature: fil_BLSSignature,
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_private_key_sign_response(
    ptr: *mut fil_PrivateKeySignResponse,
) {
    let _ = Box::from_raw(ptr);
}

/// PrivateKeyPublicKeyResponse

#[repr(C)]
pub struct fil_PrivateKeyPublicKeyResponse {
    pub public_key: fil_BLSPublicKey,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct fil_32ByteArray {
    pub inner: [u8; 32],
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_private_key_public_key_response(
    ptr: *mut fil_PrivateKeyPublicKeyResponse,
) {
    let _ = Box::from_raw(ptr);
}
