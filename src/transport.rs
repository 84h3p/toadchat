use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::sync::atomic::{AtomicU64, Ordering};

use eframe::egui::Context;
use tokio::sync::mpsc::UnboundedReceiver;
use xmpp::jid::BareJid;
use xmpp::message::send::MessageSettings;
use xmpp::parsers::iq::Iq;
use xmpp::parsers::message::Message;
use xmpp::tokio_xmpp::Stanza;
use xmpp::{ClientBuilder, Event};
use sha2::Digest;

use crate::omemo_protocol;
use crate::omemo_store::PersistentOmemoStore;
use dziber_omemo::manager::OmemoManager;
use dziber_omemo::bundle::Bundle;
use dziber_omemo::trust::TrustStatus;

static IQ_COUNTER: AtomicU64 = AtomicU64::new(1);

pub enum ClientCommand {
    SendMessage { recipient: String, body: String, encrypted: bool },
    UploadFile { recipient: String, service: String, path: PathBuf },
    FetchDevices { jid: String },
    TrustDevice { jid: String, device_id: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceTrust {
    Trusted,
    Untrusted,
    Undecided,
}

pub enum ClientEvent {
    Online,
    Disconnected(String),
    Message { sender: String, body: String, encrypted: bool },
    Sent { recipient: String, body: String, encrypted: bool },
    Contact { jid: String, name: String },
    ContactRemoved { jid: String },
    UploadComplete { recipient: String, url: String, file_name: String },
    OmemoReady { device_id: u32 },
    OmemoUnavailable(String),
    OmemoDevice { jid: String, device_id: u32, fingerprint: String, trust: DeviceTrust },
    OmemoBlocked { sender: String, reason: String },
    Info(String),
}

struct PendingUpload {
    recipient: String,
    file_name: String,
}

enum PendingOmemo {
    DeviceList { jid: String },
    Bundle { jid: String, device_id: u32 },
    BundlePublish,
}

pub fn run(
    jid: String,
    password: String,
    commands: UnboundedReceiver<ClientCommand>,
    events: Sender<ClientEvent>,
    repaint: Context,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            emit(&events, &repaint, ClientEvent::Disconnected(format!("Не удалось запустить сетевой runtime: {error}")));
            return;
        }
    };
    runtime.block_on(run_async(jid, password, commands, events, repaint));
}

async fn run_async(
    jid: String,
    password: String,
    mut commands: UnboundedReceiver<ClientCommand>,
    events: Sender<ClientEvent>,
    repaint: Context,
) {
    let bare_jid = match jid.parse::<BareJid>() {
        Ok(jid) => jid,
        Err(error) => {
            emit(&events, &repaint, ClientEvent::Disconnected(format!("Некорректный XMPP-адрес: {error}")));
            return;
        }
    };
    let own_jid = bare_jid.to_string();
    let mut agent = ClientBuilder::new(bare_jid, &password)
        .set_resource("Toadchat")
        .set_client(xmpp::ClientType::Pc, "Toadchat")
        .build();
    let mut omemo: Option<OmemoManager> = None;
    let mut pending_omemo = HashMap::<String, PendingOmemo>::new();
    let mut pending_bundles = HashMap::<(String, u32), Bundle>::new();
    let mut pending_uploads = VecDeque::<PendingUpload>::new();

    loop {
        tokio::select! {
            incoming = agent.wait_for_events() => {
                let mut encrypted_senders = HashSet::new();
                for event in incoming {
                    match event {
                        Event::Online => {
                            emit(&events, &repaint, ClientEvent::Online);
                            match PersistentOmemoStore::open_for_account(&own_jid) {
                                Ok(store) => {
                                    let mut manager = OmemoManager::load_or_generate(0, Box::new(store));
                                    manager.set_our_jid(&own_jid);
                                    manager.trust_store.set(&own_jid, manager.our_device_id(), TrustStatus::Trusted);
                                    publish_own_omemo(&mut agent, &mut manager, &mut pending_omemo, &own_jid).await;
                                    request_devices(&mut agent, &mut pending_omemo, &own_jid, true).await;
                                    emit(&events, &repaint, ClientEvent::OmemoReady { device_id: manager.our_device_id() });
                                    omemo = Some(manager);
                                }
                                Err(error) => emit(&events, &repaint, ClientEvent::OmemoUnavailable(format!("Не удалось открыть системный keyring/OMEMO storage: {error}"))),
                            }
                        }
                        Event::Disconnected(error) => {
                            if let Some(manager) = &omemo { let _ = manager.save(); }
                            emit(&events, &repaint, ClientEvent::Disconnected(format!("Соединение завершено: {error}")));
                            return;
                        }
                        Event::ContactAdded(contact) | Event::ContactChanged(contact) => {
                            let jid = contact.jid.to_string();
                            let name = contact.name.unwrap_or_else(|| jid.split('@').next().unwrap_or(&jid).to_owned());
                            emit(&events, &repaint, ClientEvent::Contact { jid, name });
                        }
                        Event::ContactRemoved(contact) => emit(&events, &repaint, ClientEvent::ContactRemoved { jid: contact.jid.to_string() }),
                        Event::Iq(iq) => {
                            process_omemo_iq(iq, &mut agent, &mut omemo, &mut pending_omemo, &mut pending_bundles, &events, &repaint).await;
                        }
                        Event::Message(message) => {
                            if has_omemo_payload(&message) {
                                let sender = message.from.as_ref().map(|jid| jid.to_bare().to_string()).unwrap_or_default();
                                encrypted_senders.insert(sender.clone());
                                process_encrypted_message(message, &sender, &mut agent, &mut omemo, &mut pending_omemo, &events, &repaint).await;
                            }
                        }
                        Event::ChatMessage(_, sender, body, _) => {
                            let sender = sender.to_string();
                            if !encrypted_senders.contains(&sender) {
                                emit(&events, &repaint, ClientEvent::Message { sender, body, encrypted: false });
                            }
                        }
                        Event::HttpUploadedFile(url) => {
                            if let Some(upload) = pending_uploads.pop_front() {
                                let recipient = match upload.recipient.parse::<BareJid>() {
                                    Ok(recipient) => recipient,
                                    Err(error) => {
                                        emit(&events, &repaint, ClientEvent::Info(format!("Некорректный адрес получателя: {error}")));
                                        continue;
                                    }
                                };
                                agent.send_message(MessageSettings::new(recipient, &url)).await;
                                emit(&events, &repaint, ClientEvent::UploadComplete { recipient: upload.recipient, url, file_name: upload.file_name });
                            } else {
                                emit(&events, &repaint, ClientEvent::Info(format!("Файл загружен: {url}")));
                            }
                        }
                        _ => {}
                    }
                }
            }
            command = commands.recv() => {
                let Some(command) = command else { return; };
                match command {
                    ClientCommand::SendMessage { recipient, body, encrypted } => {
                        let recipient_bare = match recipient.parse::<BareJid>() {
                            Ok(jid) => jid.to_string(),
                            Err(error) => {
                                emit(&events, &repaint, ClientEvent::Info(format!("Некорректный JID: {error}")));
                                continue;
                            }
                        };
                        if encrypted {
                            if !is_direct_chat_jid(&recipient_bare) {
                                emit(&events, &repaint, ClientEvent::Info("Экспериментальный legacy OMEMO разрешён только для личных чатов".to_owned()));
                                continue;
                            }
                            let Some(manager) = omemo.as_mut() else {
                                emit(&events, &repaint, ClientEvent::Info("OMEMO storage недоступно; отправка заблокирована".to_owned()));
                                continue;
                            };
                            if !peer_devices_are_trusted(manager, &recipient_bare) {
                                request_devices(&mut agent, &mut pending_omemo, &recipient_bare, false).await;
                                emit(&events, &repaint, ClientEvent::Info("Не отправлено: сначала получите и вручную проверьте OMEMO fingerprints всех устройств собеседника".to_owned()));
                                continue;
                            }
                            if recipient_bare != own_jid
                                && manager.device_lists.get(&recipient_bare).is_some_and(|devices| devices.contains(&manager.our_device_id()))
                            {
                                emit(&events, &repaint, ClientEvent::Info("Небезопасный конфликт OMEMO device_id: шифрование заблокировано".to_owned()));
                                continue;
                            }
                            if !has_sessions_for_peer_devices(manager, &recipient_bare) {
                                request_devices(&mut agent, &mut pending_omemo, &recipient_bare, false).await;
                                emit(&events, &repaint, ClientEvent::Info("Не отправлено: OMEMO ключи ещё загружаются. Повторите отправку после проверки устройств".to_owned()));
                                continue;
                            }
                            replenish_prekeys_if_needed(&mut agent, manager, &mut pending_omemo, &own_jid).await;
                            let Some(encrypted_message) = manager.encrypt_message(&recipient_bare, &body) else {
                                emit(&events, &repaint, ClientEvent::Info("OMEMO не создал шифротекст; plaintext fallback отключён, сообщение не отправлено".to_owned()));
                                continue;
                            };
                            let id = next_iq_id("message");
                            let Some(message) = omemo_protocol::encrypted_message_element(&encrypted_message, &recipient_bare, &id) else {
                                emit(&events, &repaint, ClientEvent::Info("Не удалось собрать OMEMO stanza; сообщение не отправлено".to_owned()));
                                continue;
                            };
                            match agent.send_stanza(Stanza::Message(message)).await {
                                Ok(_) => {
                                    let _ = manager.save();
                                    emit(&events, &repaint, ClientEvent::Sent { recipient: recipient_bare, body, encrypted: true });
                                }
                                Err(error) => {
                                    let _ = manager.save();
                                    emit(&events, &repaint, ClientEvent::Info(format!("XMPP не принял зашифрованное сообщение: {error}")));
                                }
                            }
                        } else {
                            agent.send_message(MessageSettings::new(recipient_bare.parse().expect("validated bare JID"), &body)).await;
                            emit(&events, &repaint, ClientEvent::Message { sender: own_jid.clone(), body, encrypted: false });
                        }
                        repaint.request_repaint();
                    }
                    ClientCommand::UploadFile { recipient, service, path } => {
                        if let Err(error) = recipient.parse::<BareJid>() {
                            emit(&events, &repaint, ClientEvent::Info(format!("Некорректный JID: {error}")));
                            continue;
                        }
                        let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or("file").to_owned();
                        pending_uploads.push_back(PendingUpload { recipient, file_name });
                        agent.upload_file_with(&service, &path).await;
                        repaint.request_repaint();
                    }
                    ClientCommand::FetchDevices { jid } => {
                        request_devices(&mut agent, &mut pending_omemo, &jid, false).await;
                    }
                    ClientCommand::TrustDevice { jid, device_id } => {
                        if let Some(manager) = omemo.as_mut() {
                            if let Some(bundle) = pending_bundles.remove(&(jid.clone(), device_id)) {
                                manager.legacy_sessions.entry(jid.clone()).or_default().remove(&device_id);
                                if !manager.create_session_from_bundle(&jid, device_id, &bundle) {
                                    emit(&events, &repaint, ClientEvent::Info("Новый bundle не прошёл криптографическую проверку; устройство осталось недоверенным".to_owned()));
                                    continue;
                                }
                            }
                            if !manager.bundle_cache.get(&jid).is_some_and(|devices| devices.contains_key(&device_id)) {
                                emit(&events, &repaint, ClientEvent::Info("Нельзя доверить устройство без проверенного bundle fingerprint".to_owned()));
                                continue;
                            }
                            manager.trust_store.set(&jid, device_id, TrustStatus::Trusted);
                            if let Some(fingerprint) = fingerprint_for(manager, &jid, device_id) {
                                emit(&events, &repaint, ClientEvent::OmemoDevice { jid: jid.clone(), device_id, fingerprint, trust: DeviceTrust::Trusted });
                            }
                            let _ = manager.save();
                        }
                    }
                }
            }
        }
    }
}

async fn publish_own_omemo(
    agent: &mut xmpp::Agent,
    manager: &mut OmemoManager,
    pending: &mut HashMap<String, PendingOmemo>,
    own_jid: &str,
) {
    let device_id = manager.our_device_id();
    let device_id_request = next_iq_id("publish-devices");
    if let Some(iq) = omemo_protocol::publish_device_list_iq(own_jid, device_id, &device_id_request) {
        let _ = agent.send_stanza(Stanza::Iq(iq)).await;
    }
    if let Some(bundle) = manager.self_bundle() {
        let request_id = next_iq_id("publish-bundle");
        if let Some(iq) = omemo_protocol::publish_bundle_iq(own_jid, &bundle, &request_id) {
            pending.insert(request_id, PendingOmemo::BundlePublish);
            if agent.send_stanza(Stanza::Iq(iq)).await.is_err() {
                pending.retain(|_, request| !matches!(request, PendingOmemo::BundlePublish));
            }
        }
    }
}

async fn replenish_prekeys_if_needed(
    agent: &mut xmpp::Agent,
    manager: &mut OmemoManager,
    pending: &mut HashMap<String, PendingOmemo>,
    own_jid: &str,
) {
    if manager.account.all_stored_one_time_keys().len() > 20
        || pending.values().any(|request| matches!(request, PendingOmemo::BundlePublish))
    {
        return;
    }
    manager.account.inner.generate_one_time_keys(100);
    manager.account.inner.generate_fallback_key();
    publish_own_omemo(agent, manager, pending, own_jid).await;
    let _ = manager.save();
}

async fn request_devices(
    agent: &mut xmpp::Agent,
    pending: &mut HashMap<String, PendingOmemo>,
    jid: &str,
    own_account: bool,
) {
    let id = next_iq_id("devices");
    if let Some(iq) = omemo_protocol::device_list_fetch_iq(jid, &id) {
        pending.insert(id, PendingOmemo::DeviceList { jid: jid.to_owned() });
        let _ = agent.send_stanza(Stanza::Iq(iq)).await;
    } else if !own_account {
        // Invalid addresses are surfaced by send controls and never receive plaintext fallback.
    }
}

async fn process_omemo_iq(
    iq: Iq,
    agent: &mut xmpp::Agent,
    manager: &mut Option<OmemoManager>,
    pending: &mut HashMap<String, PendingOmemo>,
    pending_bundles: &mut HashMap<(String, u32), Bundle>,
    events: &Sender<ClientEvent>,
    repaint: &Context,
) {
    let (id, payload) = match iq {
        Iq::Result { id, payload, .. } => (id, payload),
        Iq::Error { id, .. } => {
            match pending.remove(&id) {
                Some(PendingOmemo::DeviceList { jid }) => emit(events, repaint, ClientEvent::Info(format!("Не удалось получить OMEMO device list для {jid}"))),
                Some(PendingOmemo::BundlePublish) => emit(events, repaint, ClientEvent::OmemoUnavailable("Сервер отклонил публикацию OMEMO bundle".to_owned())),
                _ => {}
            }
            return;
        }
        _ => return,
    };
    let Some(request) = pending.remove(&id) else { return; };
    let Some(manager) = manager.as_mut() else { return; };
    let request = match request {
        PendingOmemo::BundlePublish => {
            manager.account.inner.mark_keys_as_published();
            let _ = manager.save();
            return;
        }
        request => request,
    };
    let Some(payload) = payload else {
        emit(events, repaint, ClientEvent::Info("Пустой ответ OMEMO pubsub".to_owned()));
        return;
    };

    match request {
        PendingOmemo::DeviceList { jid } => {
            let Some(devices) = omemo_protocol::parse_device_list_payload(&payload) else {
                emit(events, repaint, ClientEvent::Info(format!("Сервер не вернул поддерживаемый Conversations legacy device list для {jid}")));
                return;
            };
            let previous = manager.trust_store.all_entries().into_iter()
                .filter(|(known_jid, _, _)| known_jid == &jid)
                .map(|(_, device_id, status)| (device_id, status))
                .collect::<HashMap<_, _>>();
            manager.update_device_list(&jid, devices.clone());
            for device_id in &devices {
                let trust = if manager.our_jid.as_deref() == Some(jid.as_str()) && *device_id == manager.our_device_id() {
                    TrustStatus::Trusted
                } else {
                    previous.get(device_id).cloned().unwrap_or(TrustStatus::Undecided)
                };
                manager.trust_store.set(&jid, *device_id, trust);
                if *device_id != manager.our_device_id() || manager.our_jid.as_deref() != Some(jid.as_str()) {
                    let bundle_id = next_iq_id("bundle");
                    if let Some(bundle_iq) = omemo_protocol::bundle_fetch_iq(&jid, *device_id, &bundle_id) {
                        pending.insert(bundle_id, PendingOmemo::Bundle { jid: jid.clone(), device_id: *device_id });
                        let _ = agent.send_stanza(Stanza::Iq(bundle_iq)).await;
                    }
                }
            }
            let _ = manager.save();
        }
        PendingOmemo::Bundle { jid, device_id } => {
            let Some(bundle) = omemo_protocol::parse_bundle_payload(&payload, device_id) else {
                emit(events, repaint, ClientEvent::Info(format!("Не удалось разобрать OMEMO bundle {jid} / устройство {device_id}")));
                return;
            };
            let fingerprint = fingerprint(&bundle.ik);
            let pinned_identity = manager.bundle_cache.get(&jid).and_then(|devices| devices.get(&device_id)).map(|cached| cached.identity_key);
            if pinned_identity.is_some_and(|pinned| pinned.as_slice() != bundle.ik.as_slice()) {
                manager.trust_store.set(&jid, device_id, TrustStatus::Untrusted);
                pending_bundles.insert((jid.clone(), device_id), bundle);
                emit(events, repaint, ClientEvent::OmemoDevice { jid: jid.clone(), device_id, fingerprint, trust: DeviceTrust::Untrusted });
                emit(events, repaint, ClientEvent::Info(format!("Ключ устройства {jid}/{device_id} изменился. Новую сессию не создавали до повторной проверки fingerprint")));
                let _ = manager.save();
                return;
            }
            if !manager.create_session_from_bundle(&jid, device_id, &bundle) {
                manager.trust_store.set(&jid, device_id, TrustStatus::Untrusted);
                emit(events, repaint, ClientEvent::OmemoDevice { jid, device_id, fingerprint, trust: DeviceTrust::Untrusted });
                emit(events, repaint, ClientEvent::Info("Bundle устройства не прошёл криптографическую проверку".to_owned()));
                return;
            }
            let status = trust_status(manager, &jid, device_id);
            emit(events, repaint, ClientEvent::OmemoDevice { jid, device_id, fingerprint, trust: status });
            let _ = manager.save();
        }
        PendingOmemo::BundlePublish => unreachable!("handled above"),
    }
}

async fn process_encrypted_message(
    message: Message,
    sender: &str,
    agent: &mut xmpp::Agent,
    manager: &mut Option<OmemoManager>,
    pending: &mut HashMap<String, PendingOmemo>,
    events: &Sender<ClientEvent>,
    repaint: &Context,
) {
    let Some(manager) = manager.as_mut() else {
        emit(events, repaint, ClientEvent::OmemoBlocked { sender: sender.to_owned(), reason: "OMEMO storage недоступно".to_owned() });
        return;
    };
    let Some(encrypted) = omemo_protocol::encrypted_payload(&message) else {
        emit(events, repaint, ClientEvent::OmemoBlocked { sender: sender.to_owned(), reason: "не удалось разобрать шифротекст; fallback-текст скрыт".to_owned() });
        return;
    };
    if trust_status(manager, sender, encrypted.header.sid) != DeviceTrust::Trusted {
        request_devices(agent, pending, sender, false).await;
        emit(events, repaint, ClientEvent::OmemoBlocked { sender: sender.to_owned(), reason: format!("устройство {} не проверено; текст не показан", encrypted.header.sid) });
        return;
    }
    if let Some(key) = encrypted.header.keys.iter().flat_map(|group| &group.keys)
        .find(|key| key.rid == manager.our_device_id() && key.kex)
    {
        let claimed_identity = key.data.get(1..)
            .and_then(|bytes| dziber_omemo::signal_ratchet::proto::PreKeySignalMessage::decode(bytes).ok())
            .map(|prekey| prekey.identity_key);
        let pinned_identity = manager.bundle_cache.get(sender)
            .and_then(|bundles| bundles.get(&encrypted.header.sid))
            .map(|bundle| bundle.identity_key);
        if claimed_identity.is_none() || claimed_identity != pinned_identity {
            emit(events, repaint, ClientEvent::OmemoBlocked {
                sender: sender.to_owned(),
                reason: "PreKey identity не совпадает с проверенным bundle fingerprint; сообщение заблокировано".to_owned(),
            });
            return;
        }
    }
    match manager.decrypt_message(sender, &encrypted) {
        Some(body) => {
            let _ = manager.save();
            emit(events, repaint, ClientEvent::Message { sender: sender.to_owned(), body, encrypted: true });
        }
        None => emit(events, repaint, ClientEvent::OmemoBlocked { sender: sender.to_owned(), reason: "расшифровка не удалась; fallback-текст скрыт".to_owned() }),
    }
}

fn has_omemo_payload(message: &Message) -> bool {
    message.payloads.iter().any(|payload| payload.name() == "encrypted" && payload.ns() == omemo_protocol::OMEMO_NS)
}

fn peer_devices_are_trusted(manager: &OmemoManager, jid: &str) -> bool {
    let Some(devices) = manager.device_lists.get(jid) else { return false; };
    !devices.is_empty() && devices.iter().all(|device_id| trust_status(manager, jid, *device_id) == DeviceTrust::Trusted)
}

fn has_sessions_for_peer_devices(manager: &OmemoManager, jid: &str) -> bool {
    let Some(devices) = manager.device_lists.get(jid) else { return false; };
    let Some(sessions) = manager.legacy_sessions.get(jid) else { return false; };
    devices.iter().all(|device_id| {
        let is_our_current_device = manager.our_jid.as_deref() == Some(jid) && *device_id == manager.our_device_id();
        is_our_current_device || sessions.contains_key(device_id)
    })
}

fn trust_status(manager: &OmemoManager, jid: &str, device_id: u32) -> DeviceTrust {
    match manager.trust_store.all_entries().into_iter().find(|(known_jid, known_id, _)| known_jid == jid && *known_id == device_id).map(|(_, _, status)| status) {
        Some(TrustStatus::Trusted) => DeviceTrust::Trusted,
        Some(TrustStatus::Untrusted) => DeviceTrust::Untrusted,
        _ => DeviceTrust::Undecided,
    }
}

fn fingerprint_for(manager: &OmemoManager, jid: &str, device_id: u32) -> Option<String> {
    let identity = manager.bundle_cache.get(jid)?.get(&device_id)?.identity_key;
    Some(fingerprint(&identity))
}

fn fingerprint(identity_key: &[u8]) -> String {
    let digest = sha2::Sha256::digest(identity_key);
    digest.chunks(2).map(|part| part.iter().map(|byte| format!("{byte:02X}")).collect::<String>()).collect::<Vec<_>>().join(" ")
}

fn next_iq_id(prefix: &str) -> String {
    format!("toadchat-{prefix}-{}", IQ_COUNTER.fetch_add(1, Ordering::Relaxed))
}

fn is_direct_chat_jid(jid: &str) -> bool {
    !jid.contains("@conference.") && !jid.contains("@muc.")
}

fn emit(events: &Sender<ClientEvent>, repaint: &Context, event: ClientEvent) {
    let _ = events.send(event);
    repaint.request_repaint();
}

#[cfg(test)]
mod tests {
    use super::*;
    use dziber_omemo::store::MemoryStore;

    #[test]
    fn experimental_omemo_v0_encrypts_and_decrypts_between_devices() {
        let mut alice = OmemoManager::generate(101, Box::new(MemoryStore::new()));
        let mut bob = OmemoManager::generate(202, Box::new(MemoryStore::new()));
        alice.set_our_jid("alice@example.org");
        bob.set_our_jid("bob@example.org");

        let alice_bundle = alice.self_bundle().expect("alice bundle");
        let bob_bundle = bob.self_bundle().expect("bob bundle");
        alice.update_device_list("bob@example.org", vec![202]);
        bob.update_device_list("alice@example.org", vec![101]);
        assert!(alice.create_session_from_bundle("bob@example.org", 202, &bob_bundle));

        let encrypted = alice.encrypt_message("bob@example.org", "secret test body").expect("encryption");
        let stanza = omemo_protocol::encrypted_message_element(&encrypted, "bob@example.org", "test-message-id")
            .expect("build OMEMO XMPP stanza");
        let parsed = omemo_protocol::encrypted_payload(&stanza).expect("parse OMEMO XMPP stanza");
        assert_eq!(bob.decrypt_message("alice@example.org", &parsed).as_deref(), Some("secret test body"));

        // The sender's bundle is only used to ensure the generated identities are valid and distinct.
        assert_ne!(alice_bundle.ik, bob_bundle.ik);
    }
}
