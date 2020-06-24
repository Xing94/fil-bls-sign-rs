use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::sys::jarray;
use jni::sys::jbyte;
use jni::sys::jint;
use jni::sys::jbyteArray;
use std::slice::from_raw_parts;
use crate::bls::api::{fil_private_key_generate, PUBLIC_KEY_BYTES, fil_private_key_sign, SIGNATURE_BYTES, fil_private_key_public_key, fil_private_key_generate_with_seed, PRIVATE_KEY_BYTES, fil_BLSDigest};
use std::ffi::CString;
use std::os::raw::c_char;
use crate::bls::types;
use std::fs::copy;
use std::ptr::null;
use crate::bls::types::{fil_destroy_private_key_sign_response, fil_destroy_hash_response, fil_HashResponse};
use bls_signatures::{PrivateKey, Serialize};


#[no_mangle]
pub unsafe extern "system" fn Java_com_lxx_nativerust_FilecoinBlsSignUtil_generateBlsSeed(env: JNIEnv,
// This is the class that owns our static method. It's not going to be used,
// but still must be present to match the expected signature of a static
// native method.
                                                                                          class: JClass)
                                                                                          -> jstring {
    let private_key = (*fil_private_key_generate()).private_key.inner;

    let output = env.new_string(hex::encode(&private_key)).expect("Couldn't create java string!");

    // Finally, extract the raw pointer to return.
    output.into_inner()
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_lxx_nativerust_FilecoinBlsSignUtil_filPrivateKeyPublicKey(env: JNIEnv,
// This is the class that owns our static method. It's not going to be used,
// but still must be present to match the expected signature of a static
// native method.
                                                                                                 class: JClass,
                                                                                                 private_key_hex: JString)
                                                                                                 -> jstring {
    let private_key_j_str = env.get_string(private_key_hex).unwrap();
    let private_key_cstr = private_key_j_str.as_ref();
    private_key_j_str.as_ptr();
    let raw_private_key_ptr: *const u8 = hex::decode(private_key_cstr.to_bytes()).unwrap().as_ptr();

    let public_key = (*fil_private_key_public_key(raw_private_key_ptr)).public_key.inner;

    let out_byte = from_raw_parts(&public_key[0], PUBLIC_KEY_BYTES);

    let output = env.new_string(hex::encode(out_byte)).expect("Couldn't create java string!");
    // Finally, extract the raw pointer to return.

    output.into_inner()
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_lxx_nativerust_FilecoinBlsSignUtil_filPrivateKeyGenerateWithSeed(env: JNIEnv,
// This is the class that owns our static method. It's not going to be used,
// but still must be present to match the expected signature of a static
// native method.
                                                                                                        class: JClass,
                                                                                                        private_key_seed_hex: JString)
                                                                                                        -> jstring {
    let private_key_j_str = env.get_string(private_key_seed_hex).unwrap();
    let private_key_cstr = private_key_j_str.as_ref();
    private_key_j_str.as_ptr();
    let raw_private_key_ptr = hex::decode(private_key_cstr.to_bytes()).unwrap();

    let mut seed_array: [u8; PRIVATE_KEY_BYTES] = [0; PRIVATE_KEY_BYTES];

    for index in 0..raw_private_key_ptr.as_slice().len() {
        if index >= seed_array.len() {
            break;
        }
        seed_array[index] = raw_private_key_ptr.as_slice()[index];
    }
    raw_private_key_ptr.as_ptr();
    let seed_32array = types::fil_32ByteArray {
        inner: seed_array,
    };
    let private_key = (*fil_private_key_generate_with_seed(seed_32array)).private_key.inner;

    let out_byte = from_raw_parts(&private_key[0], PRIVATE_KEY_BYTES);

    let output = env.new_string(hex::encode(out_byte)).expect("Couldn't create java string!");
    // Finally, extract the raw pointer to return.
    output.into_inner()
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_lxx_nativerust_FilecoinBlsSignUtil_filPrivateKeySign(env: JNIEnv,
// This is the class that owns our static method. It's not going to be used,
// but still must be present to match the expected signature of a static
// native method.
                                                                                            class: JClass,
                                                                                            private_key_hex: JString,
                                                                                            message_hex: JString)
                                                                                            -> jstring {
    let private_key_j_str = env.get_string(private_key_hex).unwrap();
    let private_key_cstr = private_key_j_str.as_ref();

    let message = env.get_string(message_hex).unwrap();
    let sigmsg = hex::decode(message.as_ref().to_bytes()).unwrap();

    let msgu = sigmsg.as_ptr();

    let sign = (*fil_private_key_sign(
        hex::decode(private_key_cstr.to_bytes()).unwrap().as_ptr(),
        msgu,
        sigmsg.len())).signature.inner;

    let output = env.new_string(hex::encode(sign.as_ref())).expect("Couldn't create java string!");
    output.into_inner()
}