//! Shared RFC 9807 implementation. No WASI, filesystem, network or clock imports.
//!
//! The sole host capability fills a supplied memory slice with OS randomness.
//! Application credentials and protocol messages never enter command arguments.
use base64::{Engine, engine::general_purpose::STANDARD};
use opaque_ke::argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse,
    RegistrationUpload, Ristretto255, ServerLogin, ServerLoginParameters,
    ServerRegistration, ServerSetup, TripleDh,
};
use rand::rngs::OsRng;
use serde_json::{Value, json};
use sha2::Sha512;
use zeroize::Zeroize;

const MAX_JSON: usize = 128 * 1024;
const MAX_BINARY: usize = 4096;
const CONTEXT: &[u8] = b"chatroom/opaque/v1";
const FAILURE: &[u8] = b"{\"error\":\"authentication_failed\"}";

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "env")]
unsafe extern "C" {
    fn chatroom_random(ptr: *mut u8, len: usize) -> i32;
}

#[cfg(target_arch = "wasm32")]
fn fill_random(dest: &mut [u8]) -> Result<(), getrandom::Error> {
    // The embedding application supplies secrets.token_bytes / crypto/rand.
    if unsafe { chatroom_random(dest.as_mut_ptr(), dest.len()) } == 0 {
        Ok(())
    } else {
        Err(getrandom::Error::UNSUPPORTED)
    }
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(fill_random);

struct Suite;
impl CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

fn text<'a>(request: &'a Value, key: &str) -> Result<&'a str, ()> {
    let value = request.get(key).and_then(Value::as_str).ok_or(())?;
    if value.is_empty() || value.len() > 1024 {
        return Err(());
    }
    Ok(value)
}

fn binary(request: &Value, key: &str) -> Result<Vec<u8>, ()> {
    let value = request.get(key).and_then(Value::as_str).ok_or(())?;
    if value.is_empty() || value.len() > MAX_BINARY * 2 {
        return Err(());
    }
    let bytes = STANDARD.decode(value).map_err(|_| ())?;
    if bytes.len() > MAX_BINARY {
        return Err(());
    }
    Ok(bytes)
}

fn encode(value: impl AsRef<[u8]>) -> String {
    STANDARD.encode(value)
}

fn identifiers(request: &Value) -> Result<Identifiers<'_>, ()> {
    Ok(Identifiers {
        client: Some(text(request, "username")?.as_bytes()),
        server: Some(text(request, "server_id")?.as_bytes()),
    })
}

fn argon2() -> Result<Argon2<'static>, ()> {
    let params = Params::new(65536, 3, 1, None).map_err(|_| ())?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn execute(request: &Value) -> Result<Value, ()> {
    match text(request, "op")? {
        "server_setup" => {
            let setup = ServerSetup::<Suite>::new(&mut OsRng);
            Ok(json!({"setup": encode(setup.serialize())}))
        }
        "registration_start" => {
            let result = ClientRegistration::<Suite>::start(
                &mut OsRng,
                text(request, "password")?.as_bytes(),
            ).map_err(|_| ())?;
            Ok(json!({"state": encode(result.state.serialize()),
                      "request": encode(result.message.serialize())}))
        }
        "registration_respond" => {
            let setup = ServerSetup::<Suite>::deserialize(&binary(request, "setup")?).map_err(|_| ())?;
            let registration = RegistrationRequest::<Suite>::deserialize(&binary(request, "request")?).map_err(|_| ())?;
            // Validate both identifiers before constructing an OPRF response.
            let _ = identifiers(request)?;
            let result = ServerRegistration::<Suite>::start(
                &setup, registration, text(request, "username")?.as_bytes(),
            ).map_err(|_| ())?;
            Ok(json!({"response": encode(result.message.serialize())}))
        }
        "registration_finish" => {
            let state = ClientRegistration::<Suite>::deserialize(&binary(request, "state")?).map_err(|_| ())?;
            let response = RegistrationResponse::<Suite>::deserialize(&binary(request, "response")?).map_err(|_| ())?;
            let ksf = argon2()?;
            let result = state.finish(
                &mut OsRng,
                text(request, "password")?.as_bytes(),
                response,
                ClientRegistrationFinishParameters::new(identifiers(request)?, Some(&ksf)),
            ).map_err(|_| ())?;
            Ok(json!({"record": encode(result.message.serialize()),
                      "export_key": encode(result.export_key)}))
        }
        "record_validate" => {
            let upload = RegistrationUpload::<Suite>::deserialize(&binary(request, "record")?).map_err(|_| ())?;
            let record = ServerRegistration::<Suite>::finish(upload);
            Ok(json!({"record": encode(record.serialize())}))
        }
        "login_start" => {
            let result = ClientLogin::<Suite>::start(
                &mut OsRng, text(request, "password")?.as_bytes(),
            ).map_err(|_| ())?;
            Ok(json!({"state": encode(result.state.serialize()),
                      "request": encode(result.message.serialize())}))
        }
        "login_respond" => {
            let setup = ServerSetup::<Suite>::deserialize(&binary(request, "setup")?).map_err(|_| ())?;
            let record = if request.get("record").is_none_or(Value::is_null) {
                None
            } else {
                Some(ServerRegistration::<Suite>::deserialize(&binary(request, "record")?).map_err(|_| ())?)
            };
            let credential = CredentialRequest::<Suite>::deserialize(&binary(request, "request")?).map_err(|_| ())?;
            let result = ServerLogin::<Suite>::start(
                &mut OsRng, &setup, record, credential,
                text(request, "username")?.as_bytes(),
                ServerLoginParameters { context: Some(CONTEXT), identifiers: identifiers(request)? },
            ).map_err(|_| ())?;
            Ok(json!({"state": encode(result.state.serialize()),
                      "response": encode(result.message.serialize())}))
        }
        "login_finish" => {
            let state = ClientLogin::<Suite>::deserialize(&binary(request, "state")?).map_err(|_| ())?;
            let response = CredentialResponse::<Suite>::deserialize(&binary(request, "response")?).map_err(|_| ())?;
            let ksf = argon2()?;
            let result = state.finish(
                &mut OsRng,
                text(request, "password")?.as_bytes(),
                response,
                ClientLoginFinishParameters::new(Some(CONTEXT), identifiers(request)?, Some(&ksf)),
            ).map_err(|_| ())?;
            Ok(json!({"finalization": encode(result.message.serialize()),
                      "export_key": encode(result.export_key),
                      "session_key": encode(result.session_key)}))
        }
        "login_verify" => {
            let state = ServerLogin::<Suite>::deserialize(&binary(request, "state")?).map_err(|_| ())?;
            let finalization = CredentialFinalization::<Suite>::deserialize(&binary(request, "finalization")?).map_err(|_| ())?;
            // Identifiers and context are already authenticated in serialized KE2 state.
            let result = state.finish(finalization, ServerLoginParameters::default()).map_err(|_| ())?;
            Ok(json!({"session_key": encode(result.session_key)}))
        }
        _ => Err(()),
    }
}

fn erase(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(erase),
        Value::Object(values) => values.values_mut().for_each(erase),
        _ => (),
    }
}

fn process(input: &[u8]) -> Vec<u8> {
    if input.is_empty() || input.len() > MAX_JSON {
        return FAILURE.to_vec();
    }
    let mut request: Value = match serde_json::from_slice(input) {
        Ok(value) => value,
        Err(_) => return FAILURE.to_vec(),
    };
    let mut response = execute(&request).unwrap_or_else(|_| json!({"error": "authentication_failed"}));
    let output = serde_json::to_vec(&response).unwrap_or_else(|_| FAILURE.to_vec());
    erase(&mut request);
    erase(&mut response);
    if output.len() > MAX_JSON { FAILURE.to_vec() } else { output }
}

/// Allocations belong to the caller, including output allocations returned by run.
#[unsafe(no_mangle)]
pub extern "C" fn alloc(len: u32) -> u32 {
    if len == 0 || len as usize > MAX_JSON { return 0; }
    Box::into_raw(vec![0u8; len as usize].into_boxed_slice()) as *mut u8 as usize as u32
}

/// The caller must pass an allocation and its original length exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dealloc(ptr: u32, len: u32) {
    if ptr == 0 || len == 0 || len as usize > MAX_JSON { return; }
    let raw = std::ptr::slice_from_raw_parts_mut(ptr as usize as *mut u8, len as usize);
    let mut allocation = unsafe { Box::from_raw(raw) };
    allocation.zeroize();
}

/// Returns output pointer in the high 32 bits and output length in the low bits.
/// Input remains owned by the caller and is not freed by this function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn run(ptr: u32, len: u32) -> u64 {
    let result = if ptr == 0 || len == 0 || len as usize > MAX_JSON {
        FAILURE.to_vec()
    } else {
        process(unsafe { std::slice::from_raw_parts(ptr as usize as *const u8, len as usize) })
    };
    let len = result.len() as u64;
    let ptr = Box::into_raw(result.into_boxed_slice()) as *mut u8 as usize as u64;
    (ptr << 32) | len
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(op: &str, fields: Value) -> Value {
        let mut fields = fields;
        fields["op"] = json!(op);
        execute(&fields).expect("operation should succeed")
    }

    #[test]
    fn opaque_roundtrip_and_wrong_password() {
        let setup = op("server_setup", json!({}));
        let password = "synthetic-test-password";
        let start = op("registration_start", json!({"password":password}));
        let response = op("registration_respond", json!({"setup":setup["setup"],"username":"alice","server_id":"test-server","request":start["request"]}));
        let finish = op("registration_finish", json!({"password":password,"state":start["state"],"response":response["response"],"username":"alice","server_id":"test-server"}));
        let record = op("record_validate", json!({"record":finish["record"]}));
        assert_eq!(finish["record"], record["record"]);
        let login = op("login_start", json!({"password":password}));
        let response = op("login_respond", json!({"setup":setup["setup"],"record":record["record"],"username":"alice","server_id":"test-server","request":login["request"]}));
        let complete = op("login_finish", json!({"password":password,"state":login["state"],"response":response["response"],"username":"alice","server_id":"test-server"}));
        let verified = op("login_verify", json!({"state":response["state"],"finalization":complete["finalization"]}));
        assert_eq!(complete["session_key"], verified["session_key"]);
        assert_eq!(complete["export_key"], finish["export_key"]);
        let login = op("login_start", json!({"password":"wrong-password"}));
        let response = op("login_respond", json!({"setup":setup["setup"],"record":record["record"],"username":"alice","server_id":"test-server","request":login["request"]}));
        let failed = execute(&json!({"op":"login_finish","password":"wrong-password","state":login["state"],"response":response["response"],"username":"alice","server_id":"test-server"}));
        assert!(failed.is_err());
    }

    #[test]
    fn fixed_failures_do_not_echo_inputs() {
        assert_eq!(process(b"invalid-json"), FAILURE);
        assert_eq!(process(br#"{"op":"login_finish","password":"synthetic-secret"}"#), FAILURE);
        assert_eq!(process(&vec![b'x'; MAX_JSON + 1]), FAILURE);
    }
}
