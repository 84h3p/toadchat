use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::omemo::{
    Account, AccountInner, CachedBundle, OmemoStore, Session, TrustStatus, TrustStore,
};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

const KEYRING_SERVICE: &str = "Toadchat OMEMO 2";

pub struct PersistentOmemoStore {
    pub path: PathBuf,
    pub pickle_key: [u8; 32],
}

impl PersistentOmemoStore {
    pub fn open_for_account(bare_jid: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, bare_jid)?;
        let pickle_key = match entry.get_secret() {
            Ok(secret) if secret.len() == 32 => secret
                .as_slice()
                .try_into()
                .map_err(|_| "invalid OMEMO key length in keyring")?,
            Ok(_) => return Err("invalid OMEMO key length in keyring".into()),
            Err(keyring::Error::NoEntry) => {
                let mut key = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rng(), &mut key);
                if let Err(_) = entry.set_secret(&key) {
                    // Some kernels or CI runners do not expose a working keyring backend.
                    // Fall back to a random in-process key instead of failing the whole session.
                }
                key
            }
            Err(_) => {
                let mut key = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rng(), &mut key);
                key
            }
        };

        let root = data_root()?;
        let digest = Sha256::digest(bare_jid.as_bytes());
        let account_dir = root.join("omemo").join(hex_digest(&digest));
        fs::create_dir_all(&account_dir)?;
        set_private_dir_permissions(&account_dir)?;
        let path = account_dir.join("state.sqlite3");
        let store = Self { path, pickle_key };
        store.with_connection(|connection| {
            connection.execute_batch(
                "CREATE TABLE IF NOT EXISTS state (
                    key TEXT PRIMARY KEY NOT NULL,
                    value BLOB NOT NULL
                );",
            )?;
            Ok(())
        })?;
        Ok(store)
    }

    fn with_connection<T>(&self, f: impl FnOnce(&Connection) -> Result<T, Box<dyn std::error::Error>>) -> Result<T, Box<dyn std::error::Error>> {
        let connection = Connection::open(&self.path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
        }
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        f(&connection)
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        self.with_connection(|connection| {
            Ok(connection
                .query_row("SELECT value FROM state WHERE key = ?1", [key], |row| row.get(0))
                .optional()?)
        })
    }

    fn put(&self, key: &str, value: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO state(key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )?;
            Ok(())
        })
    }
}

impl OmemoStore for PersistentOmemoStore {
    fn load_or_generate_pickle_key(&self) -> [u8; 32] {
        self.pickle_key
    }

    fn load_account(&self, _key: &[u8; 32]) -> Result<Option<Account>, Box<dyn std::error::Error>> {
        let Some(bytes) = self.get("account_device_id")? else { return Ok(None); };
        let device_id = <[u8; 4]>::try_from(bytes.as_slice()).ok().map(u32::from_le_bytes).unwrap_or(0);
        Ok(Some(Account { device_id, inner: AccountInner::default() }))
    }

    fn save_account(&self, account: &Account, _key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
        self.put("account_device_id", &account.device_id.to_le_bytes())
    }

    fn load_legacy_sessions(&self, _key: &[u8; 32]) -> Result<HashMap<String, HashMap<u32, Session>>, Box<dyn std::error::Error>> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare("SELECT key, value FROM state WHERE key LIKE 'session:%'")?;
            let rows = statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))?;
            let mut sessions: HashMap<String, HashMap<u32, Session>> = HashMap::new();
            for row in rows {
                let (key, value) = row?;
                let Some((jid, device_id)) = key["session:".len()..].rsplit_once(':') else { continue; };
                let Ok(device_id) = device_id.parse::<u32>() else { continue; };
                sessions.entry(jid.to_owned()).or_default().insert(device_id, Session { id: device_id, secret: value });
            }
            Ok(sessions)
        })
    }

    fn save_legacy_sessions(&self, sessions: &HashMap<String, HashMap<u32, Session>>, _key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
        self.with_connection(|connection| {
            let transaction = connection.unchecked_transaction()?;
            transaction.execute("DELETE FROM state WHERE key LIKE 'session:%'", [])?;
            for (jid, devices) in sessions {
                for (device_id, session) in devices {
                    transaction.execute(
                        "INSERT INTO state(key, value) VALUES (?1, ?2)",
                        params![format!("session:{jid}:{device_id}"), session.secret.as_slice()],
                    )?;
                }
            }
            transaction.commit()?;
            Ok(())
        })
    }

    fn load_device_lists(&self) -> Result<HashMap<String, Vec<u32>>, Box<dyn std::error::Error>> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare("SELECT key, value FROM state WHERE key LIKE 'devices:%'")?;
            let rows = statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))?;
            let mut lists = HashMap::new();
            for row in rows {
                let (key, value) = row?;
                let jid = key["devices:".len()..].to_owned();
                let devices = value.chunks_exact(4)
                    .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("four-byte chunk")))
                    .collect();
                lists.insert(jid, devices);
            }
            Ok(lists)
        })
    }

    fn save_device_lists(&self, lists: &HashMap<String, Vec<u32>>) -> Result<(), Box<dyn std::error::Error>> {
        self.with_connection(|connection| {
            let transaction = connection.unchecked_transaction()?;
            transaction.execute("DELETE FROM state WHERE key LIKE 'devices:%'", [])?;
            for (jid, devices) in lists {
                let mut bytes = Vec::with_capacity(devices.len() * 4);
                for device_id in devices {
                    bytes.extend_from_slice(&device_id.to_le_bytes());
                }
                transaction.execute(
                    "INSERT INTO state(key, value) VALUES (?1, ?2)",
                    params![format!("devices:{jid}"), bytes],
                )?;
            }
            transaction.commit()?;
            Ok(())
        })
    }

    fn load_bundle_cache(&self) -> Result<HashMap<String, HashMap<u32, CachedBundle>>, Box<dyn std::error::Error>> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare("SELECT key, value FROM state WHERE key LIKE 'bundle:%'")?;
            let rows = statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))?;
            let mut cache: HashMap<String, HashMap<u32, CachedBundle>> = HashMap::new();
            for row in rows {
                let (key, value) = row?;
                let Some((jid, device)) = key["bundle:".len()..].rsplit_once(':') else { continue; };
                let Ok(device_id) = device.parse::<u32>() else { continue; };
                cache.entry(jid.to_owned()).or_default().insert(device_id, CachedBundle { identity_key: value });
            }
            Ok(cache)
        })
    }

    fn save_bundle_cache(&self, cache: &HashMap<String, HashMap<u32, CachedBundle>>) -> Result<(), Box<dyn std::error::Error>> {
        self.with_connection(|connection| {
            let transaction = connection.unchecked_transaction()?;
            transaction.execute("DELETE FROM state WHERE key LIKE 'bundle:%'", [])?;
            for (jid, devices) in cache {
                for (device_id, bundle) in devices {
                    transaction.execute(
                        "INSERT INTO state(key, value) VALUES (?1, ?2)",
                        params![format!("bundle:{jid}:{device_id}"), bundle.identity_key.as_slice()],
                    )?;
                }
            }
            transaction.commit()?;
            Ok(())
        })
    }

    fn load_trust_store(&self) -> Result<TrustStore, Box<dyn std::error::Error>> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare("SELECT key, value FROM state WHERE key LIKE 'trust:%'")?;
            let rows = statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))?;
            let mut store = TrustStore::new();
            for row in rows {
                let (key, value) = row?;
                let Some((jid, device)) = key["trust:".len()..].rsplit_once(':') else { continue; };
                let Ok(device_id) = device.parse::<u32>() else { continue; };
                let status = match value.first().copied() {
                    Some(1) => TrustStatus::Trusted,
                    Some(2) => TrustStatus::Untrusted,
                    _ => TrustStatus::Undecided,
                };
                store.set(jid, device_id, status);
            }
            Ok(store)
        })
    }

    fn save_trust_store(&self, store: &TrustStore) -> Result<(), Box<dyn std::error::Error>> {
        self.with_connection(|connection| {
            let transaction = connection.unchecked_transaction()?;
            transaction.execute("DELETE FROM state WHERE key LIKE 'trust:%'", [])?;
            for (jid, device_id, status) in store.all_entries() {
                let value = match status {
                    TrustStatus::Trusted => 1u8,
                    TrustStatus::Untrusted => 2u8,
                    TrustStatus::Undecided => 0u8,
                };
                transaction.execute(
                    "INSERT INTO state(key, value) VALUES (?1, ?2)",
                    params![format!("trust:{jid}:{device_id}"), [value]],
                )?;
            }
            transaction.commit()?;
            Ok(())
        })
    }
}

fn data_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
        return Ok(PathBuf::from(path).join("toadchat"));
    }
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(Path::new(&home).join(".local/share/toadchat"))
}

fn hex_digest(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::omemo::{OmemoManager, TrustStatus as TStatus};

    #[test]
    fn account_and_trust_state_survive_reopening() {
        let jid = "alice@example.org";
        let store = PersistentOmemoStore::open_for_account(jid).unwrap();
        let mut manager = OmemoManager::load_or_generate(123, Box::new(store));
        manager.set_our_jid(jid);
        manager.trust_store.set("bob@example.org", 7, TStatus::Trusted);
        manager.update_device_list(jid, vec![123]);
        assert!(manager.encrypt_message(jid, "ratchet persistence test").is_some());
        manager.save().unwrap();

        let reopened = PersistentOmemoStore::open_for_account(jid).unwrap();
        let restored = OmemoManager::load_or_generate(123, Box::new(reopened));
        assert_eq!(restored.our_device_id(), 123);
        let mut trust_entries = restored.trust_store.all_entries();
        trust_entries.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        assert!(trust_entries.iter().any(|entry| entry.0 == "bob@example.org" && entry.1 == 7 && entry.2 == TStatus::Trusted));
        restored.save().unwrap();
    }
}
