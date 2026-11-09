mod omemo;
mod transport;
mod omemo_protocol;
mod omemo_store;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};

use eframe::egui::{self, Align, Color32, CornerRadius, FontId, Layout, RichText, Stroke, Vec2};
use transport::{ClientCommand, ClientEvent};

const BG: Color32 = Color32::from_rgb(246, 247, 250);
const PANEL: Color32 = Color32::WHITE;
const TEXT: Color32 = Color32::from_rgb(28, 31, 38);
const MUTED: Color32 = Color32::from_rgb(132, 139, 151);
const BLUE: Color32 = Color32::from_rgb(48, 119, 255);
const LINE: Color32 = Color32::from_rgb(232, 235, 240);

#[derive(Clone)]
struct ChatMessage {
    body: String,
    time: String,
    outgoing: bool,
    attachment: bool,
    encrypted: bool,
}

#[derive(Clone)]
struct OmemoDeviceInfo {
    jid: String,
    device_id: u32,
    fingerprint: String,
    trust: transport::DeviceTrust,
}

#[derive(Clone)]
struct Contact {
    name: String,
    jid: String,
    preview: String,
    time: String,
    color: Color32,
    online: bool,
    unread: usize,
    messages: Vec<ChatMessage>,
}

#[derive(PartialEq)]
enum Screen {
    SignIn,
    Chats,
}

struct ToadchatApp {
    screen: Screen,
    jid: String,
    password: String,
    upload_service: String,
    search: String,
    draft: String,
    selected: usize,
    contacts: Vec<Contact>,
    is_online: bool,
    status: String,
    show_settings: bool,
    show_security: bool,
    show_new_chat: bool,
    new_chat_jid: String,
    demo_mode: bool,
    encrypted_chats: HashSet<String>,
    pending_uploads: HashSet<String>,
    omemo_devices: Vec<OmemoDeviceInfo>,
    omemo_status: String,
    command_tx: Option<tokio::sync::mpsc::UnboundedSender<ClientCommand>>,
    event_rx: Receiver<ClientEvent>,
    event_tx: Sender<ClientEvent>,
    toast: Option<(String, f64)>,
}

impl Default for ToadchatApp {
    fn default() -> Self {
        let (event_tx, event_rx) = mpsc::channel();
        Self {
            screen: Screen::SignIn,
            jid: String::new(),
            password: String::new(),
            upload_service: String::new(),
            search: String::new(),
            draft: String::new(),
            selected: 0,
            contacts: demo_contacts(),
            is_online: false,
            status: "Не подключено".to_owned(),
            show_settings: false,
            show_security: false,
            show_new_chat: false,
            new_chat_jid: String::new(),
            demo_mode: false,
            encrypted_chats: HashSet::new(),
            pending_uploads: HashSet::new(),
            omemo_devices: Vec::new(),
            omemo_status: "OMEMO выключено".to_owned(),
            command_tx: None,
            event_rx,
            event_tx,
            toast: None,
        }
    }
}

impl ToadchatApp {
    fn start_connection(&mut self, ctx: &egui::Context) {
        if self.jid.trim().is_empty() || self.password.is_empty() {
            self.toast = Some(("Введите XMPP-адрес и пароль".to_owned(), 3.0));
            return;
        }

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.command_tx = Some(tx);
        self.status = "Подключаемся…".to_owned();
        let events = self.event_tx.clone();
        let repaint = ctx.clone();
        let jid = self.jid.trim().to_owned();
        let password = std::mem::take(&mut self.password);
        std::thread::spawn(move || transport::run(jid, password, rx, events, repaint));
        self.screen = Screen::Chats;
    }

    fn send_draft(&mut self) {
        let body = self.draft.trim().to_owned();
        if body.is_empty() {
            return;
        }
        if self.demo_mode {
            let chat = &mut self.contacts[self.selected];
            chat.messages.push(ChatMessage {
                body: body.clone(),
                time: "Сейчас".to_owned(),
                outgoing: true,
                attachment: false,
                encrypted: false,
            });
            chat.preview = body;
            chat.time = "Сейчас".to_owned();
            self.draft.clear();
        } else if let Some(tx) = &self.command_tx {
            let recipient = self.contacts[self.selected].jid.clone();
            let encrypted = self.encrypted_chats.contains(&recipient);
            match tx.send(ClientCommand::SendMessage { recipient, body: body.clone(), encrypted }) {
                Ok(()) => {
                    if !encrypted {
                        let chat = &mut self.contacts[self.selected];
                        chat.messages.push(ChatMessage {
                            body: body.clone(),
                            time: "Сейчас".to_owned(),
                            outgoing: true,
                            attachment: false,
                            encrypted: false,
                        });
                        chat.preview = body;
                        chat.time = "Сейчас".to_owned();
                        self.draft.clear();
                    }
                }
                Err(_) => self.toast = Some(("Соединение потеряно".to_owned(), 3.0)),
            }
        }
    }

    fn choose_attachment(&mut self) {
        if self.selected < self.contacts.len() && self.encrypted_chats.contains(&self.contacts[self.selected].jid) {
            self.toast = Some(("Файлы OMEMO 2 не реализованы. Отключите OMEMO, чтобы загрузить файл (ссылка будет доступна серверу upload).".to_owned(), 6.0));
            return;
        }
        if !self.demo_mode && !self.is_online {
            self.toast = Some(("Сначала подключитесь к XMPP".to_owned(), 3.0));
            return;
        }
        if !self.demo_mode && self.upload_service.trim().is_empty() {
            self.toast = Some(("Укажите XEP-0363 upload-сервис в настройках".to_owned(), 4.0));
            self.show_settings = true;
            return;
        }
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            self.upload_file(path);
        }
    }

    fn upload_file(&mut self, path: PathBuf) {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("Файл").to_owned();
        if self.demo_mode {
            self.contacts[self.selected].messages.push(ChatMessage {
                body: name,
                time: "Сейчас".to_owned(),
                outgoing: true,
                attachment: true,
                encrypted: false,
            });
            self.toast = Some(("Демо: файл не загружался".to_owned(), 3.0));
            return;
        }
        if let Some(tx) = &self.command_tx {
            let recipient = self.contacts[self.selected].jid.clone();
            let service = self.upload_service.trim().to_owned();
            match tx.send(ClientCommand::UploadFile { recipient, service, path }) {
                Ok(()) => {
                    self.pending_uploads.insert(self.contacts[self.selected].jid.clone());
                    self.toast = Some((format!("Загружаем {name}…"), 3.0));
                }
                Err(_) => self.toast = Some(("Не удалось начать загрузку".to_owned(), 3.0)),
            }
        }
    }

    fn poll_events(&mut self, ctx: &egui::Context) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                ClientEvent::Online => {
                    self.is_online = true;
                    self.demo_mode = false;
                    self.contacts.clear();
                    self.selected = 0;
                    self.status = "В сети".to_owned();
                    self.toast = Some(("Подключение установлено".to_owned(), 3.0));
                }
                ClientEvent::Disconnected(reason) => {
                    self.is_online = false;
                    self.status = "Нет соединения".to_owned();
                    self.toast = Some((reason, 5.0));
                }
                ClientEvent::Message { sender, body, encrypted } => {
                    let index = self.contacts.iter().position(|c| c.jid == sender).unwrap_or_else(|| {
                        self.contacts.push(Contact {
                            name: sender.split('@').next().unwrap_or(&sender).to_owned(),
                            jid: sender.clone(),
                            preview: body.clone(),
                            time: "Сейчас".to_owned(),
                            color: Color32::from_rgb(141, 112, 246),
                            online: true,
                            unread: 0,
                            messages: Vec::new(),
                        });
                        self.contacts.len() - 1
                    });
                    let selected = self.selected == index;
                    let chat = &mut self.contacts[index];
                    chat.preview = body.clone();
                    chat.time = "Сейчас".to_owned();
                    if !selected { chat.unread += 1; }
                    chat.messages.push(ChatMessage {
                        body,
                        time: "Сейчас".to_owned(),
                        outgoing: false,
                        attachment: false,
                        encrypted,
                    });
                    ctx.request_repaint();
                }
                ClientEvent::Sent { recipient, body, encrypted } => {
                    if let Some(index) = self.contacts.iter().position(|contact| contact.jid == recipient) {
                        let chat = &mut self.contacts[index];
                        chat.preview = body.clone();
                        chat.time = "Сейчас".to_owned();
                        chat.messages.push(ChatMessage {
                            body: body.clone(),
                            time: "Сейчас".to_owned(),
                            outgoing: true,
                            attachment: false,
                            encrypted,
                        });
                        if self.selected == index && self.draft == body { self.draft.clear(); }
                    }
                    ctx.request_repaint();
                }
                ClientEvent::Contact { jid, name } => {
                    if let Some(contact) = self.contacts.iter_mut().find(|contact| contact.jid == jid) {
                        contact.name = name;
                    } else {
                        let color = avatar_color(&name);
                        self.contacts.push(Contact {
                            name,
                            jid,
                            preview: "Начните разговор".to_owned(),
                            time: String::new(),
                            color,
                            online: false,
                            unread: 0,
                            messages: Vec::new(),
                        });
                    }
                }
                ClientEvent::ContactRemoved { jid } => {
                    self.contacts.retain(|contact| contact.jid != jid);
                    self.selected = self.selected.min(self.contacts.len().saturating_sub(1));
                }
                ClientEvent::UploadComplete { recipient, url, file_name } => {
                    self.pending_uploads.remove(&recipient);
                    if let Some(tx) = &self.command_tx {
                        let _ = tx.send(ClientCommand::SendMessage { recipient: recipient.clone(), body: url.clone(), encrypted: false });
                    }
                    if let Some(index) = self.contacts.iter().position(|c| c.jid == recipient) {
                        self.contacts[index].messages.push(ChatMessage {
                            body: format!("{file_name}\n{url}"),
                            time: "Сейчас".to_owned(),
                            outgoing: true,
                            attachment: true,
                            encrypted: false,
                        });
                        self.contacts[index].preview = format!("Файл: {file_name}");
                    }
                    self.toast = Some((format!("Файл загружен: {file_name}"), 4.0));
                }
                ClientEvent::OmemoReady { device_id } => {
                    self.omemo_status = format!("OMEMO 2 · устройство {device_id}");
                }
                ClientEvent::OmemoUnavailable(reason) => {
                    self.omemo_status = "OMEMO storage недоступно".to_owned();
                    self.toast = Some((reason, 6.0));
                }
                ClientEvent::OmemoDevice { jid, device_id, fingerprint, trust } => {
                    if let Some(device) = self.omemo_devices.iter_mut().find(|device| device.jid == jid && device.device_id == device_id) {
                        device.fingerprint = fingerprint;
                        device.trust = trust;
                    } else {
                        self.omemo_devices.push(OmemoDeviceInfo { jid, device_id, fingerprint, trust });
                    }
                }
                ClientEvent::OmemoBlocked { sender, reason } => {
                    self.toast = Some((format!("Зашифрованное сообщение от {sender}: {reason}"), 6.0));
                }
                ClientEvent::Info(message) => self.toast = Some((message, 4.0)),
            }
        }
    }

    fn show_sign_in(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().frame(egui::Frame::new().fill(BG)).show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(48.0);
                logo(ui, 58.0);
                ui.add_space(16.0);
                ui.label(RichText::new("Toadchat").size(34.0).strong().color(TEXT));
                ui.add_space(8.0);
                ui.label(RichText::new("Твои разговоры. Твои правила.").size(16.0).color(MUTED));
                ui.add_space(32.0);

                egui::Frame::new().fill(PANEL).corner_radius(CornerRadius::same(22)).stroke(Stroke::new(1.0_f32, LINE)).inner_margin(egui::Margin::same(28)).show(ui, |ui| {
                    ui.set_max_width(380.0);
                    ui.label(RichText::new("Войти в аккаунт").size(20.0).strong().color(TEXT));
                    ui.add_space(16.0);
                    field_label(ui, "XMPP-адрес");
                    ui.add_sized([ui.available_width(), 44.0], egui::TextEdit::singleline(&mut self.jid).hint_text("имя@сервер.org"));
                    ui.add_space(12.0);
                    field_label(ui, "Пароль");
                    ui.add_sized([ui.available_width(), 44.0], egui::TextEdit::singleline(&mut self.password).password(true).hint_text("Пароль аккаунта"));
                    ui.add_space(20.0);
                    if primary_button(ui, "Подключиться") { self.start_connection(ctx); }
                    ui.add_space(10.0);
                    if ui.add(egui::Button::new(RichText::new("Посмотреть демо-интерфейс").color(BLUE)).frame(false)).clicked() {
                        self.demo_mode = true;
                        self.screen = Screen::Chats;
                        self.status = "Демо-режим".to_owned();
                    }
                    ui.add_space(8.0);
                    ui.label(RichText::new("Пароль используется только для входа и не сохраняется.").size(12.0).color(MUTED));
                });
                ui.add_space(22.0);
                ui.label(RichText::new("Открытая сеть XMPP · без привязки к одному сервису").size(12.0).color(MUTED));
            });
        });
    }

    fn show_chats(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("sidebar").exact_width(300.0).resizable(false).frame(egui::Frame::new().fill(PANEL).inner_margin(egui::Margin::same(18)).stroke(Stroke::new(1.0_f32, LINE))).show(ctx, |ui| {
            ui.horizontal(|ui| {
                logo(ui, 31.0);
                ui.label(RichText::new("Toadchat").size(20.0).strong().color(TEXT));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if icon_button(ui, Icon::Settings, 34.0, MUTED, "Настройки").clicked() { self.show_settings = !self.show_settings; }
                    if icon_button(ui, Icon::Plus, 34.0, BLUE, "Новый разговор").clicked() { self.show_new_chat = true; }
                });
            });
            ui.add_space(24.0);
            ui.label(RichText::new("СООБЩЕНИЯ").size(11.0).strong().color(MUTED));
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                draw_icon(ui, Icon::Search, 16.0, MUTED);
                ui.add_sized([ui.available_width(), 38.0], egui::TextEdit::singleline(&mut self.search).hint_text("Поиск чатов"));
            });
            ui.add_space(14.0);

            egui::ScrollArea::vertical().show(ui, |ui| {
                let query = self.search.to_lowercase();
                for index in 0..self.contacts.len() {
                    let contact = &self.contacts[index];
                    if !query.is_empty() && !contact.name.to_lowercase().contains(&query) && !contact.jid.to_lowercase().contains(&query) { continue; }
                    let selected = self.selected == index;
                    let frame = if selected { egui::Frame::new().fill(Color32::from_rgb(241, 246, 255)).corner_radius(CornerRadius::same(14)).inner_margin(egui::Margin::same(9)) } else { egui::Frame::new().inner_margin(egui::Margin::same(9)) };
                    let response = frame.show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            avatar(ui, &contact.name, contact.color, 44.0, contact.online);
                            ui.add_space(10.0);
                            ui.vertical(|ui| {
                                ui.set_width((ui.available_width() - 54.0).max(80.0));
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(&contact.name).size(14.0).strong().color(TEXT));
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| ui.label(RichText::new(&contact.time).size(11.0).color(MUTED)));
                                });
                                ui.add_space(3.0);
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(&contact.preview).size(12.0).color(MUTED));
                                    if contact.unread > 0 { ui.label(RichText::new(contact.unread.to_string()).size(10.0).color(Color32::WHITE).background_color(BLUE)); }
                                });
                            });
                        });
                    });
                    if ui.interact(response.response.rect, ui.id().with(index), egui::Sense::click()).clicked() {
                        self.selected = index;
                        self.contacts[index].unread = 0;
                    }
                    ui.add_space(3.0);
                }
            });
            ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                        let dot = if self.is_online { Color32::from_rgb(47, 190, 122) } else { MUTED };
                        status_dot(ui, dot);
                    ui.label(RichText::new(if self.demo_mode { "Демо-режим" } else { &self.status }).size(12.0).color(MUTED));
                });
            });
        });

        if self.contacts.is_empty() {
            egui::CentralPanel::default().frame(egui::Frame::new().fill(BG)).show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(ui.available_height() * 0.28);
                    logo(ui, 52.0);
                    ui.add_space(16.0);
                    ui.label(RichText::new("Начните разговор").size(23.0).strong().color(TEXT));
                    ui.add_space(6.0);
                    ui.label(RichText::new("Добавьте человека по его XMPP-адресу.").size(14.0).color(MUTED));
                    ui.add_space(18.0);
                    if ui.add(egui::Button::new(RichText::new("Новый разговор").strong().color(Color32::WHITE)).fill(BLUE).corner_radius(12)).clicked() { self.show_new_chat = true; }
                });
            });
            self.draw_dialogs(ctx);
            self.draw_toast(ctx);
            return;
        }

        egui::CentralPanel::default().frame(egui::Frame::new().fill(BG).inner_margin(egui::Margin::same(0))).show(ctx, |ui| {
            if self.contacts.is_empty() { return; }
            let contact = &self.contacts[self.selected];
            let contact_jid = contact.jid.clone();
            let omemo_enabled = self.encrypted_chats.contains(&contact_jid);
            egui::TopBottomPanel::top("chat_header").frame(egui::Frame::new().fill(PANEL).inner_margin(egui::Margin { left: 24, right: 24, top: 16, bottom: 16 }).stroke(Stroke::new(1.0_f32, LINE))).show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    avatar(ui, &contact.name, contact.color, 42.0, contact.online);
                    ui.add_space(8.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new(&contact.name).size(16.0).strong().color(TEXT));
                        ui.label(RichText::new(if contact.online { "В сети" } else { &contact.jid }).size(12.0).color(MUTED));
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        small_icon_button(ui, Icon::More, "Дополнительные действия");
                        let call = icon_button_enabled(ui, Icon::Video, 36.0, MUTED, false, "Видеозвонки пока не подключены");
                        call.on_hover_text("Звонки по XMPP Jingle пока не подключены");
                        let audio = icon_button_enabled(ui, Icon::Phone, 36.0, MUTED, false, "Аудиозвонки пока не подключены");
                        audio.on_hover_text("Аудиозвонки пока не подключены");
                        let color = if omemo_enabled { Color32::from_rgb(38, 135, 95) } else { MUTED };
                        let can_toggle_omemo = self.is_online && !self.demo_mode
                            && !contact_jid.contains("@conference.") && !contact_jid.contains("@muc.")
                            && !self.pending_uploads.contains(&contact_jid);
                        let label = if omemo_enabled { "OMEMO 2" } else { "TLS only" };
                        let lock = if omemo_enabled { Icon::Lock } else { Icon::Unlock };
                        let mut toggle_omemo = false;
                        ui.horizontal(|ui| {
                            draw_icon(ui, lock, 15.0, color);
                            let mut button = ui.add_enabled(can_toggle_omemo, egui::Button::new(RichText::new(label).size(12.0).color(color)).corner_radius(10));
                            if !can_toggle_omemo && (contact_jid.contains("@conference.") || contact_jid.contains("@muc.")) { button = button.on_hover_text("OMEMO 2 поддерживает только личные чаты"); }
                            if !can_toggle_omemo && self.pending_uploads.contains(&contact_jid) { button = button.on_hover_text("Дождитесь завершения загрузки: XEP-0363 не шифрует файл"); }
                            toggle_omemo = button.clicked();
                        });
                        if toggle_omemo {
                            if omemo_enabled {
                                self.encrypted_chats.remove(&contact_jid);
                            } else {
                                self.encrypted_chats.insert(contact_jid.clone());
                                if let Some(tx) = &self.command_tx { let _ = tx.send(ClientCommand::FetchDevices { jid: contact_jid.clone() }); }
                            }
                            self.show_security = true;
                        }
                    });
                });
            });

            let messages = self.contacts[self.selected].messages.clone();
            egui::CentralPanel::default().frame(egui::Frame::new().fill(BG).inner_margin(egui::Margin { left: 34, right: 34, top: 18, bottom: 10 })).show_inside(ui, |ui| {
                egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(6.0);
                        ui.label(RichText::new("СЕГОДНЯ").size(10.0).strong().color(MUTED));
                    });
                    ui.add_space(18.0);
                    for message in messages {
                        ui.horizontal(|ui| {
                            if message.outgoing { ui.add_space((ui.available_width() * 0.22).max(30.0)); }
                            let bg = if message.outgoing { Color32::from_rgb(225, 238, 255) } else { PANEL };
                            egui::Frame::new().fill(bg).corner_radius(CornerRadius::same(16)).stroke(Stroke::new(1.0_f32, if message.outgoing { Color32::from_rgb(220, 232, 251) } else { LINE })).inner_margin(egui::Margin { left: 14, right: 14, top: 10, bottom: 8 }).show(ui, |ui| {
                                ui.set_max_width(460.0);
                                if message.attachment {
                                    ui.horizontal(|ui| {
                                        draw_icon(ui, Icon::Paperclip, 16.0, MUTED);
                                        ui.label(RichText::new(&message.body).size(14.0).color(TEXT));
                                    });
                                } else {
                                    ui.label(RichText::new(&message.body).size(14.0).color(TEXT));
                                }
                                if message.encrypted {
                                    ui.horizontal(|ui| {
                                        draw_icon(ui, Icon::Lock, 13.0, Color32::from_rgb(38, 135, 95));
                                        ui.label(RichText::new("OMEMO 2").size(10.0).color(Color32::from_rgb(38, 135, 95)));
                                    });
                                } else if omemo_enabled {
                                    ui.horizontal(|ui| {
                                        draw_icon(ui, Icon::Warning, 13.0, Color32::from_rgb(190, 110, 30));
                                        ui.label(RichText::new("Не зашифровано OMEMO").size(10.0).color(Color32::from_rgb(190, 110, 30)));
                                    });
                                }
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| ui.label(RichText::new(&message.time).size(10.0).color(MUTED)));
                            });
                            if !message.outgoing { ui.add_space((ui.available_width() * 0.15).max(24.0)); }
                        });
                        ui.add_space(8.0);
                    }
                });
            });

            egui::TopBottomPanel::bottom("composer").frame(egui::Frame::new().fill(BG).inner_margin(egui::Margin { left: 24, right: 24, top: 8, bottom: 18 })).show_inside(ui, |ui| {
                egui::Frame::new().fill(PANEL).corner_radius(CornerRadius::same(20)).stroke(Stroke::new(1.0_f32, LINE)).inner_margin(egui::Margin::same(9)).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let attach = icon_button(ui, Icon::Paperclip, 38.0, MUTED, "Прикрепить файл");
                        if attach.clicked() { self.choose_attachment(); }
                        let response = ui.add_sized([ui.available_width() - 100.0, 40.0], egui::TextEdit::singleline(&mut self.draft).hint_text("Написать сообщение…").frame(false));
                        let enter = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        let send = send_button(ui, self.is_online || self.demo_mode);
                        if send.clicked() || (enter && (self.is_online || self.demo_mode)) { self.send_draft(); }
                    });
                });
                ui.horizontal(|ui| {
                    let encrypted = self.encrypted_chats.contains(&self.contacts[self.selected].jid);
                    ui.label(RichText::new(if encrypted { "OMEMO 2 · TLS защищает транспорт" } else { "Только TLS до сервера · OMEMO выключено" }).size(11.0).color(MUTED));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| ui.label(RichText::new(&self.omemo_status).size(11.0).color(MUTED)));
                });
            });
        });

        self.draw_dialogs(ctx);
        self.draw_toast(ctx);
    }

    fn draw_dialogs(&mut self, ctx: &egui::Context) {
        if self.show_new_chat {
            egui::Window::new("Новый разговор").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
                ui.set_width(330.0);
                ui.label("Введите полный XMPP-адрес собеседника.");
                ui.add_space(8.0);
                ui.text_edit_singleline(&mut self.new_chat_jid);
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.button("Отмена").clicked() { self.show_new_chat = false; }
                    if ui.button("Открыть чат").clicked() {
                        let jid = self.new_chat_jid.trim().to_owned();
                        if jid.contains('@') {
                            let name = jid.split('@').next().unwrap_or(&jid).to_owned();
                            if let Some(index) = self.contacts.iter().position(|contact| contact.jid == jid) {
                                self.selected = index;
                            } else {
                                self.contacts.push(Contact {
                                    name,
                                    jid,
                                    preview: "Новый разговор".to_owned(),
                                    time: "Сейчас".to_owned(),
                                    color: Color32::from_rgb(141, 112, 246),
                                    online: false,
                                    unread: 0,
                                    messages: Vec::new(),
                                });
                                self.selected = self.contacts.len() - 1;
                            }
                            self.new_chat_jid.clear();
                            self.show_new_chat = false;
                        } else {
                            self.toast = Some(("Введите полный адрес вида user@server.org".to_owned(), 3.0));
                        }
                    }
                });
            });
        }
        if self.show_settings {
            egui::Window::new("Настройки подключения").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
                ui.set_width(350.0);
                ui.label(RichText::new("HTTP File Upload (XEP-0363)").strong().color(TEXT));
                ui.add_space(8.0);
                ui.label(RichText::new("Адрес upload-компонента вашего сервера. Например, upload.example.org.").size(12.0).color(MUTED));
                ui.add_space(8.0);
                ui.text_edit_singleline(&mut self.upload_service);
                ui.add_space(12.0);
                if ui.button("Готово").clicked() { self.show_settings = false; }
            });
        }
        if self.show_security {
            let selected_jid = self.contacts.get(self.selected).map(|contact| contact.jid.clone()).unwrap_or_default();
            let devices: Vec<_> = self.omemo_devices.iter().filter(|device| device.jid == selected_jid).cloned().collect();
            egui::Window::new("Безопасность соединения").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
                ui.set_width(360.0);
                ui.label(RichText::new("OMEMO 2 / XEP-0384").size(17.0).strong().color(Color32::from_rgb(38, 135, 95)));
                ui.add_space(8.0);
                ui.label("Слой мигрирован на современный OMEMO 2 и FFI-bridge к libomemo-c. Для доверенных устройств используйте отдельную проверку fingerprint по безопасному каналу связи. Самостоятельная проверка остаётся обязательной.");
                ui.add_space(8.0);
                ui.label(RichText::new("Для зашифрованной отправки должны быть проверены все устройства собеседника. Если ключи не готовы или сообщение не шифруется, оно не отправляется открытым текстом.").strong().color(TEXT));
                if devices.is_empty() {
                    ui.add_space(8.0);
                    ui.label(RichText::new(format!("Устройства для {selected_jid} пока не получены. Включите OMEMO в заголовке чата, чтобы запросить список.")).size(12.0).color(MUTED));
                }
                for device in devices {
                    ui.separator();
                    ui.label(RichText::new(format!("{} · устройство {}", device.jid, device.device_id)).strong());
                    ui.label(RichText::new(&device.fingerprint).monospace().size(11.0));
                    let trust_label = match device.trust {
                        transport::DeviceTrust::Trusted => "Доверено",
                        transport::DeviceTrust::Untrusted => "Отклонено",
                        transport::DeviceTrust::Undecided => "Не проверено",
                    };
                    ui.label(RichText::new(format!("Статус: {trust_label}")).size(11.0).color(MUTED));
                    if device.trust != transport::DeviceTrust::Trusted
                        && ui.button("Сверил fingerprint — доверять").clicked()
                    {
                        if let Some(tx) = &self.command_tx {
                            let _ = tx.send(ClientCommand::TrustDevice { jid: device.jid.clone(), device_id: device.device_id });
                        }
                    }
                }
                ui.add_space(12.0);
                if ui.button("Понятно").clicked() { self.show_security = false; }
            });
        }
    }

    fn draw_toast(&mut self, ctx: &egui::Context) {
        if let Some((text, remaining)) = &mut self.toast {
            egui::Area::new(egui::Id::new("toast")).anchor(egui::Align2::CENTER_BOTTOM, Vec2::new(0.0, -22.0)).show(ctx, |ui| {
                egui::Frame::new().fill(Color32::from_rgb(35, 40, 50)).corner_radius(CornerRadius::same(13)).inner_margin(egui::Margin::symmetric(16, 11)).show(ui, |ui| {
                    ui.label(RichText::new(text.as_str()).color(Color32::WHITE).size(13.0));
                });
            });
            *remaining -= ctx.input(|i| i.unstable_dt as f64);
            if *remaining <= 0.0 { self.toast = None; }
            ctx.request_repaint();
        }
    }
}

impl eframe::App for ToadchatApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_events(ctx);
        if self.screen == Screen::SignIn { self.show_sign_in(ctx); } else { self.show_chats(ctx); }
    }
}

fn main() -> eframe::Result<()> {
    let mut options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1180.0, 780.0]).with_min_inner_size([800.0, 560.0]),
        renderer: eframe::Renderer::Wgpu,
        ..Default::default()
    };
    #[cfg(target_os = "linux")]
    if let egui_wgpu::WgpuSetup::CreateNew(setup) = &mut options.wgpu_options.wgpu_setup {
        // Avoid the GLES/EGL fallback, which panics in wgpu-hal on some Linux systems.
        setup.instance_descriptor.backends = wgpu::Backends::VULKAN;
    }
    eframe::run_native("Toadchat", options, Box::new(|cc| {
        cc.egui_ctx.set_visuals(egui::Visuals::light());
        cc.egui_ctx.style_mut(|style| {
            style.visuals.window_fill = PANEL;
            style.visuals.panel_fill = BG;
            style.visuals.widgets.noninteractive.bg_fill = PANEL;
            style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT);
            style.visuals.selection.bg_fill = Color32::from_rgb(210, 228, 255);
            style.spacing.item_spacing = Vec2::new(8.0, 8.0);
            style.text_styles.insert(egui::TextStyle::Body, FontId::proportional(14.0));
        });
        Ok(Box::<ToadchatApp>::default())
    }))
}

fn demo_contacts() -> Vec<Contact> {
    vec![
        Contact {
            name: "Алиса Морозова".into(), jid: "alisa@jabber.ru".into(), preview: "Скинула фотографии с прогулки".into(), time: "12:42".into(), color: Color32::from_rgb(244, 140, 157), online: true, unread: 2,
            messages: vec![
                ChatMessage { body: "Привет! Как тебе вчерашний концерт?".into(), time: "12:38".into(), outgoing: false, attachment: false, encrypted: false },
                ChatMessage { body: "Очень понравился свет и звук. Надо будет повторить!".into(), time: "12:39".into(), outgoing: true, attachment: false, encrypted: false },
                ChatMessage { body: "Скинула фотографии с прогулки".into(), time: "12:42".into(), outgoing: false, attachment: false, encrypted: false },
            ],
        },
        Contact {
            name: "Марк".into(), jid: "mark@xmpp.org".into(), preview: "Договорились, до встречи!".into(), time: "Вчера".into(), color: Color32::from_rgb(88, 168, 146), online: false, unread: 0,
            messages: vec![ChatMessage { body: "Договорились, до встречи!".into(), time: "Вчера".into(), outgoing: false, attachment: false, encrypted: false }],
        },
        Contact {
            name: "Семья".into(), jid: "family@conference.example.org".into(), preview: "Мама: В воскресенье всех жду на обед".into(), time: "Вт".into(), color: Color32::from_rgb(245, 180, 90), online: true, unread: 0,
            messages: vec![ChatMessage { body: "Мама: В воскресенье всех жду на обед".into(), time: "Вт".into(), outgoing: false, attachment: false, encrypted: false }],
        },
        Contact {
            name: "Илья".into(), jid: "ilya@jabber.org".into(), preview: "Голосовое сообщение · 0:18".into(), time: "Пн".into(), color: Color32::from_rgb(126, 144, 231), online: false, unread: 0,
            messages: vec![ChatMessage { body: "Голосовое сообщение · 0:18".into(), time: "Пн".into(), outgoing: false, attachment: true, encrypted: false }],
        },
    ]
}

fn avatar_color(name: &str) -> Color32 {
    let palette = [
        Color32::from_rgb(244, 140, 157),
        Color32::from_rgb(88, 168, 146),
        Color32::from_rgb(245, 180, 90),
        Color32::from_rgb(126, 144, 231),
        Color32::from_rgb(141, 112, 246),
    ];
    let seed = name.bytes().fold(0usize, |acc, byte| acc.wrapping_add(byte as usize));
    palette[seed % palette.len()]
}

fn field_label(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(12.0).strong().color(TEXT));
    ui.add_space(6.0);
}

fn primary_button(ui: &mut egui::Ui, label: &str) -> bool {
    ui.add_sized([ui.available_width(), 44.0], egui::Button::new(RichText::new(label).size(14.0).strong().color(Color32::WHITE)).fill(BLUE).corner_radius(12)).clicked()
}

fn logo(ui: &mut egui::Ui, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.circle_filled(rect.center(), size * 0.48, BLUE);
    painter.text(rect.center(), egui::Align2::CENTER_CENTER, "t", FontId::proportional(size * 0.68), Color32::WHITE);
}

fn avatar(ui: &mut egui::Ui, name: &str, color: Color32, size: f32, online: bool) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.circle_filled(rect.center(), size * 0.48, color);
    let initial = name.chars().find(|c| c.is_alphanumeric()).unwrap_or('?').to_uppercase().to_string();
    painter.text(rect.center(), egui::Align2::CENTER_CENTER, initial, FontId::proportional(size * 0.42), Color32::WHITE);
    if online {
        painter.circle_filled(rect.right_bottom() - Vec2::splat(3.0), size * 0.13, Color32::from_rgb(55, 193, 128));
        painter.circle_stroke(rect.right_bottom() - Vec2::splat(3.0), size * 0.13, Stroke::new(1.5_f32, PANEL));
    }
}

#[derive(Clone, Copy)]
enum Icon {
    Settings,
    Plus,
    Search,
    More,
    Video,
    Phone,
    Lock,
    Unlock,
    Paperclip,
    Send,
    Warning,
}

fn small_icon_button(ui: &mut egui::Ui, icon: Icon, description: &str) {
    let _ = icon_button(ui, icon, 34.0, MUTED, description);
}

fn icon_button(ui: &mut egui::Ui, icon: Icon, size: f32, color: Color32, description: &str) -> egui::Response {
    icon_button_enabled(ui, icon, size, color, true, description)
}

fn send_button(ui: &mut egui::Ui, enabled: bool) -> egui::Response {
    let sense = if enabled { egui::Sense::click() } else { egui::Sense::hover() };
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(40.0), sense);
    let fill = if enabled { BLUE } else { Color32::from_rgb(174, 193, 224) };
    ui.painter().rect_filled(rect, CornerRadius::same(12), fill);
    draw_icon_in_rect(ui, Icon::Send, rect.shrink(10.0), Color32::WHITE);
    response.on_hover_text("Отправить")
}

fn icon_button_enabled(
    ui: &mut egui::Ui,
    icon: Icon,
    size: f32,
    color: Color32,
    enabled: bool,
    description: &str,
) -> egui::Response {
    let sense = if enabled { egui::Sense::click() } else { egui::Sense::hover() };
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), sense);
    if response.hovered() && enabled {
        ui.painter().rect_filled(rect, CornerRadius::same(9), Color32::from_rgb(240, 243, 248));
    }
    draw_icon_in_rect(ui, icon, rect.shrink(size * 0.28), color);
    response.on_hover_text(description)
}

fn draw_icon(ui: &mut egui::Ui, icon: Icon, size: f32, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    draw_icon_in_rect(ui, icon, rect.shrink(size * 0.08), color);
}

fn status_dot(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(10.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 3.5, color);
}

fn draw_icon_in_rect(ui: &egui::Ui, icon: Icon, rect: egui::Rect, color: Color32) {
    let painter = ui.painter();
    let stroke = Stroke::new((rect.width() / 10.0).clamp(1.4, 2.0), color);
    let center = rect.center();
    let x = rect.left();
    let y = rect.top();
    let w = rect.width();
    let h = rect.height();
    let p = |px: f32, py: f32| egui::pos2(x + px * w, y + py * h);

    match icon {
        Icon::Plus => {
            painter.line_segment([p(0.5, 0.15), p(0.5, 0.85)], stroke);
            painter.line_segment([p(0.15, 0.5), p(0.85, 0.5)], stroke);
        }
        Icon::More => {
            for dx in [0.2, 0.5, 0.8] { painter.circle_filled(p(dx, 0.5), stroke.width * 1.1, color); }
        }
        Icon::Search => {
            painter.circle_stroke(p(0.43, 0.42), w * 0.27, stroke);
            painter.line_segment([p(0.63, 0.63), p(0.90, 0.90)], stroke);
        }
        Icon::Settings => {
            painter.circle_stroke(center, w * 0.28, stroke);
            painter.circle_filled(center, w * 0.08, color);
            for angle in 0..8 {
                let radians = angle as f32 * std::f32::consts::TAU / 8.0;
                let direction = Vec2::new(radians.cos(), radians.sin());
                painter.line_segment([center + direction * w * 0.35, center + direction * w * 0.48], stroke);
            }
        }
        Icon::Video => {
            painter.rect_stroke(egui::Rect::from_min_max(p(0.12, 0.25), p(0.66, 0.75)), CornerRadius::same(2), stroke, egui::StrokeKind::Inside);
            painter.add(egui::Shape::line(vec![p(0.70, 0.38), p(0.91, 0.25), p(0.91, 0.75), p(0.70, 0.62)], stroke));
        }
        Icon::Phone => {
            painter.add(egui::Shape::line(vec![p(0.25, 0.12), p(0.16, 0.20), p(0.20, 0.42), p(0.35, 0.64), p(0.58, 0.80), p(0.80, 0.84), p(0.89, 0.75)], stroke));
            painter.line_segment([p(0.18, 0.18), p(0.38, 0.38)], stroke);
            painter.line_segment([p(0.62, 0.62), p(0.82, 0.82)], stroke);
        }
        Icon::Lock | Icon::Unlock => {
            painter.rect_stroke(egui::Rect::from_min_max(p(0.20, 0.44), p(0.80, 0.91)), CornerRadius::same(3), stroke, egui::StrokeKind::Inside);
            let shackle = if matches!(icon, Icon::Lock) {
                vec![p(0.32, 0.46), p(0.32, 0.30), p(0.40, 0.15), p(0.60, 0.15), p(0.68, 0.30), p(0.68, 0.46)]
            } else {
                vec![p(0.68, 0.46), p(0.68, 0.30), p(0.60, 0.15), p(0.43, 0.15), p(0.33, 0.27)]
            };
            painter.add(egui::Shape::line(shackle, stroke));
            painter.circle_filled(p(0.50, 0.64), stroke.width * 0.9, color);
        }
        Icon::Paperclip => {
            painter.add(egui::Shape::line(vec![p(0.65, 0.25), p(0.35, 0.58), p(0.35, 0.72), p(0.46, 0.80), p(0.58, 0.76), p(0.79, 0.53), p(0.80, 0.40), p(0.73, 0.33), p(0.64, 0.34), p(0.43, 0.56)], stroke));
        }
        Icon::Send => {
            painter.add(egui::Shape::line(vec![p(0.12, 0.18), p(0.88, 0.50), p(0.12, 0.82), p(0.28, 0.53), p(0.66, 0.50), p(0.28, 0.47), p(0.12, 0.18)], stroke));
        }
        Icon::Warning => {
            painter.add(egui::Shape::line(vec![p(0.50, 0.08), p(0.94, 0.88), p(0.06, 0.88), p(0.50, 0.08)], stroke));
            painter.line_segment([p(0.50, 0.34), p(0.50, 0.60)], stroke);
            painter.circle_filled(p(0.50, 0.73), stroke.width * 0.75, color);
        }
    }
}
