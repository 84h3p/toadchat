use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc::Sender;

use tokio::sync::mpsc::UnboundedReceiver;
use eframe::egui::Context;
use xmpp::jid::BareJid;
use xmpp::message::send::MessageSettings;
use xmpp::{ClientBuilder, Event};

pub enum ClientCommand {
    SendMessage { recipient: String, body: String },
    UploadFile { recipient: String, service: String, path: PathBuf },
}

pub enum ClientEvent {
    Online,
    Disconnected(String),
    Message { sender: String, body: String },
    Contact { jid: String, name: String },
    ContactRemoved { jid: String },
    UploadComplete { recipient: String, url: String, file_name: String },
    Info(String),
}

struct PendingUpload {
    recipient: String,
    file_name: String,
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
            let _ = events.send(ClientEvent::Disconnected(format!("Не удалось запустить сетевой runtime: {error}")));
            repaint.request_repaint();
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
            let _ = events.send(ClientEvent::Disconnected(format!("Некорректный XMPP-адрес: {error}")));
            repaint.request_repaint();
            return;
        }
    };

    let mut agent = ClientBuilder::new(bare_jid, &password)
        .set_resource("Toadchat")
        .set_client(xmpp::ClientType::Pc, "Toadchat")
        .build();
    let mut pending_uploads = VecDeque::<PendingUpload>::new();

    loop {
        tokio::select! {
            incoming = agent.wait_for_events() => {
                for event in incoming {
                    match event {
                        Event::Online => { let _ = events.send(ClientEvent::Online); }
                        Event::Disconnected(error) => {
                            let _ = events.send(ClientEvent::Disconnected(format!("Соединение завершено: {error}")));
                            repaint.request_repaint();
                            return;
                        }
                        Event::ChatMessage(_, sender, body, _) => {
                            let _ = events.send(ClientEvent::Message {
                                sender: sender.to_string(),
                                body,
                            });
                        }
                        Event::ContactAdded(contact) | Event::ContactChanged(contact) => {
                            let jid = contact.jid.to_string();
                            let name = contact.name.unwrap_or_else(|| jid.split('@').next().unwrap_or(&jid).to_owned());
                            let _ = events.send(ClientEvent::Contact { jid, name });
                        }
                        Event::ContactRemoved(contact) => {
                            let _ = events.send(ClientEvent::ContactRemoved { jid: contact.jid.to_string() });
                        }
                        Event::HttpUploadedFile(url) => {
                            if let Some(upload) = pending_uploads.pop_front() {
                                let recipient = match upload.recipient.parse::<BareJid>() {
                                    Ok(recipient) => recipient,
                                    Err(error) => {
                                        let _ = events.send(ClientEvent::Info(format!("Некорректный адрес получателя: {error}")));
                                        continue;
                                    }
                                };
                                agent.send_message(MessageSettings::new(recipient, &url)).await;
                                let _ = events.send(ClientEvent::UploadComplete {
                                    recipient: upload.recipient,
                                    url,
                                    file_name: upload.file_name,
                                });
                            } else {
                                let _ = events.send(ClientEvent::Info(format!("Файл загружен: {url}")));
                            }
                        }
                        _ => {}
                    }
                    repaint.request_repaint();
                }
            }
            command = commands.recv() => {
                let Some(command) = command else { return; };
                match command {
                    ClientCommand::SendMessage { recipient, body } => {
                        match recipient.parse::<BareJid>() {
                            Ok(recipient) => agent.send_message(MessageSettings::new(recipient, &body)).await,
                            Err(error) => { let _ = events.send(ClientEvent::Info(format!("Некорректный JID: {error}"))); }
                        }
                        repaint.request_repaint();
                    }
                    ClientCommand::UploadFile { recipient, service, path } => {
                        if let Err(error) = recipient.parse::<BareJid>() {
                            let _ = events.send(ClientEvent::Info(format!("Некорректный JID: {error}")));
                            continue;
                        }
                        let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or("file").to_owned();
                        pending_uploads.push_back(PendingUpload { recipient, file_name });
                        agent.upload_file_with(&service, &path).await;
                        repaint.request_repaint();
                    }
                }
            }
        }
    }
}
