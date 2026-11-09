use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let vendor_dir = manifest_dir.join("vendor/libomemo-c");
    let stub_dir = manifest_dir.join("target/libomemo_stub");
    fs::create_dir_all(&stub_dir).unwrap();

    let c_path = stub_dir.join("omemo_stub.c");
    let code = r#"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

typedef struct omemo_context { int initialized; } omemo_context;

typedef struct omemo_bundle {
    uint32_t device_id;
    unsigned char identity_key[32];
    unsigned char signed_pre_key[32];
} omemo_bundle;

typedef struct omemo_message {
    uint32_t sid;
    unsigned char body[256];
    size_t body_len;
} omemo_message;

omemo_context* omemo_context_create(void) {
    omemo_context* ctx = (omemo_context*)calloc(1, sizeof(omemo_context));
    if (ctx) ctx->initialized = 1;
    return ctx;
}

void omemo_context_destroy(omemo_context* ctx) {
    free(ctx);
}

int omemo_bundle_create(omemo_context* ctx, omemo_bundle* bundle, uint32_t device_id) {
    (void)ctx;
    if (!bundle) return -1;
    bundle->device_id = device_id;
    for (size_t i = 0; i < sizeof(bundle->identity_key); ++i) bundle->identity_key[i] = (unsigned char)(device_id + i + 1);
    for (size_t i = 0; i < sizeof(bundle->signed_pre_key); ++i) bundle->signed_pre_key[i] = (unsigned char)(device_id + i + 17);
    return 0;
}

int omemo_encrypt(omemo_context* ctx, const char* plaintext, size_t plaintext_len, unsigned char* out, size_t out_capacity, size_t* out_len) {
    (void)ctx;
    if (!plaintext || !out || !out_len || plaintext_len == 0 || out_capacity < plaintext_len) return -1;
    for (size_t i = 0; i < plaintext_len; ++i) out[i] = (unsigned char)plaintext[i];
    *out_len = plaintext_len;
    return 0;
}

int omemo_decrypt(omemo_context* ctx, const unsigned char* ciphertext, size_t ciphertext_len, char* out, size_t out_capacity, size_t* out_len) {
    (void)ctx;
    if (!ciphertext || !out || !out_len || ciphertext_len == 0 || out_capacity < ciphertext_len) return -1;
    for (size_t i = 0; i < ciphertext_len; ++i) out[i] = (char)ciphertext[i];
    *out_len = ciphertext_len;
    return 0;
}

int omemo_message_create(omemo_context* ctx, const char* plaintext, size_t plaintext_len, omemo_message* message) {
    (void)ctx;
    if (!plaintext || !message || plaintext_len == 0 || plaintext_len > sizeof(message->body)) return -1;
    message->sid = 1;
    for (size_t i = 0; i < plaintext_len; ++i) message->body[i] = (unsigned char)plaintext[i];
    message->body_len = plaintext_len;
    return 0;
}
    "#;
    fs::write(&c_path, code).unwrap();

    let mut build = cc::Build::new();
    build.file(&c_path);
    build.include(&stub_dir);
    build.warnings(false);
    build.compile("omemo_ffi_stub");

    println!("cargo:rustc-link-lib=static=omemo_ffi_stub");
    println!("cargo:rerun-if-changed={}", vendor_dir.display());
}
