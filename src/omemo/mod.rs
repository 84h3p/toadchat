use std::collections::HashMap;
use std::error::Error;

pub mod ffi;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustStatus {
    Trusted,
    Untrusted,
    Undecided,
}

#[derive(Clone, Default, Debug)]
pub struct TrustStore {
    entries: HashMap<(String, u32), TrustStatus>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, jid: &str, device_id: u32, status: TrustStatus) {
        self.entries.insert((jid.to_owned(), device_id), status);
    }

    pub fn all_entries(&self) -> Vec<(String, u32, TrustStatus)> {
        self.entries
            .iter()
            .map(|((jid, device_id), status)| (jid.clone(), *device_id, *status))
            .collect()
    }

    pub fn get(&self, jid: &str, device_id: u32) -> Option<TrustStatus> {
        self.entries.get(&(jid.to_owned(), device_id)).copied()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Session {
    pub id: u32,
    pub secret: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct CachedBundle {
    pub identity_key: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct Bundle {
    pub device_id: u32,
    pub ik: Vec<u8>,
    pub spk: Vec<u8>,
    pub opk: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Default)]
pub struct EncryptedKey {
    pub rid: u32,
    pub data: Vec<u8>,
    pub kex: bool,
}

#[derive(Clone, Debug, Default)]
pub struct EncryptedHeader {
    pub sid: u32,
    pub keys: Vec<EncryptedKey>,
}

#[derive(Clone, Debug, Default)]
pub struct EncryptedMessage {
    pub header: EncryptedHeader,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct AccountInner {
    pub generated_keys: Vec<Vec<u8>>,
    pub published: bool,
}

impl AccountInner {
    pub fn generate_one_time_keys(&mut self, count: usize) {
        self.generated_keys = (0..count)
            .map(|index| format!("omemo-otk-{index}").into_bytes())
            .collect();
    }

    pub fn generate_fallback_key(&mut self) {
        self.generated_keys.push(b"omemo-fallback".to_vec());
    }

    pub fn all_stored_one_time_keys(&self) -> &[Vec<u8>] {
        &self.generated_keys
    }

    pub fn mark_keys_as_published(&mut self) {
        self.published = true;
    }
}

#[derive(Clone, Debug, Default)]
pub struct Account {
    pub device_id: u32,
    pub inner: AccountInner,
}

impl Account {
    pub fn all_stored_one_time_keys(&self) -> &[Vec<u8>] {
        self.inner.all_stored_one_time_keys()
    }
}

pub trait OmemoStore: Send + Sync {
    fn load_or_generate_pickle_key(&self) -> [u8; 32];
    fn load_account(&self, key: &[u8; 32]) -> Result<Option<Account>, Box<dyn Error>>;
    fn save_account(&self, account: &Account, key: &[u8; 32]) -> Result<(), Box<dyn Error>>;
    fn load_legacy_sessions(&self, key: &[u8; 32]) -> Result<HashMap<String, HashMap<u32, Session>>, Box<dyn Error>>;
    fn save_legacy_sessions(&self, sessions: &HashMap<String, HashMap<u32, Session>>, key: &[u8; 32]) -> Result<(), Box<dyn Error>>;
    fn load_device_lists(&self) -> Result<HashMap<String, Vec<u32>>, Box<dyn Error>>;
    fn save_device_lists(&self, lists: &HashMap<String, Vec<u32>>) -> Result<(), Box<dyn Error>>;
    fn load_bundle_cache(&self) -> Result<HashMap<String, HashMap<u32, CachedBundle>>, Box<dyn Error>>;
    fn save_bundle_cache(&self, cache: &HashMap<String, HashMap<u32, CachedBundle>>) -> Result<(), Box<dyn Error>>;
    fn load_trust_store(&self) -> Result<TrustStore, Box<dyn Error>>;
    fn save_trust_store(&self, store: &TrustStore) -> Result<(), Box<dyn Error>>;
}

pub struct OmemoManager {
    pub account: Account,
    pub our_jid: Option<String>,
    pub trust_store: TrustStore,
    pub device_lists: HashMap<String, Vec<u32>>,
    pub legacy_sessions: HashMap<String, HashMap<u32, Session>>,
    pub bundle_cache: HashMap<String, HashMap<u32, CachedBundle>>,
    pub store: Option<Box<dyn OmemoStore>>,
}

impl OmemoManager {
    pub fn load_or_generate(device_id: u32, store: Box<dyn OmemoStore>) -> Self {
        let key = store.load_or_generate_pickle_key();
        let account = match store.load_account(&key).unwrap_or(None) {
            Some(account) => account,
            None => Account { device_id, inner: AccountInner::default() },
        };
        let trust_store = store.load_trust_store().unwrap_or_else(|_| TrustStore::new());
        let device_lists = store.load_device_lists().unwrap_or_default();
        let bundle_cache = store.load_bundle_cache().unwrap_or_default();
        let legacy_sessions = store.load_legacy_sessions(&key).unwrap_or_default();
        Self {
            account,
            our_jid: None,
            trust_store,
            device_lists,
            legacy_sessions,
            bundle_cache,
            store: Some(store),
        }
    }

    pub fn set_our_jid(&mut self, jid: &str) {
        self.our_jid = Some(jid.to_owned());
    }

    pub fn our_device_id(&self) -> u32 {
        self.account.device_id
    }

    pub fn self_bundle(&self) -> Option<Bundle> {
        let bundle = ffi::OmemoFfiContext::new().ok()?;
        let ffi_bundle = bundle.generate_bundle(self.account.device_id).ok()?;
        Some(Bundle {
            device_id: ffi_bundle.device_id,
            ik: ffi_bundle.identity_key.to_vec(),
            spk: ffi_bundle.signed_pre_key.to_vec(),
            opk: vec![],
        })
    }

    pub fn update_device_list(&mut self, jid: &str, devices: Vec<u32>) {
        self.device_lists.insert(jid.to_owned(), devices);
    }

    pub fn create_session_from_bundle(&mut self, jid: &str, device_id: u32, bundle: &Bundle) -> bool {
        let identity = bundle.ik.clone();
        self.bundle_cache
            .entry(jid.to_owned())
            .or_default()
            .insert(device_id, CachedBundle { identity_key: identity });
        self.legacy_sessions
            .entry(jid.to_owned())
            .or_default()
            .insert(device_id, Session { id: device_id, secret: bundle.spk.clone() });
        true
    }

    pub fn encrypt_message(&mut self, recipient: &str, body: &str) -> Option<EncryptedMessage> {
        let _ = recipient;
        let ffi = ffi::OmemoFfiContext::new().ok()?;
        let payload = ffi.encrypt(body).ok()?;
        let key = EncryptedKey {
            rid: self.account.device_id,
            data: payload,
            kex: true,
        };
        Some(EncryptedMessage {
            header: EncryptedHeader { sid: self.account.device_id, keys: vec![key] },
            payload: body.as_bytes().to_vec(),
        })
    }

    pub fn decrypt_message(&mut self, sender: &str, encrypted: &EncryptedMessage) -> Option<String> {
        let _ = sender;
        let ffi = ffi::OmemoFfiContext::new().ok()?;
        let used = encrypted.payload.clone();
        let plaintext = ffi.decrypt(&used).ok()?;
        if plaintext.is_empty() {
            return None;
        }
        Some(plaintext)
    }

    pub fn save(&self) -> Result<(), String> {
        let Some(store) = self.store.as_ref() else {
            return Ok(());
        };
        let key = store.load_or_generate_pickle_key();
        let account = self.account.clone();
        store.save_account(&account, &key).map_err(|error| error.to_string())?;
        store.save_legacy_sessions(&self.legacy_sessions, &key).map_err(|error| error.to_string())?;
        store.save_device_lists(&self.device_lists).map_err(|error| error.to_string())?;
        store.save_bundle_cache(&self.bundle_cache).map_err(|error| error.to_string())?;
        store.save_trust_store(&self.trust_store).map_err(|error| error.to_string())?;
        Ok(())
    }
}
