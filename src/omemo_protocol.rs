use crate::omemo::{Bundle, EncryptedHeader, EncryptedKey, EncryptedMessage};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use xmpp::jid::Jid;
use xmpp::minidom::Element;
use xmpp::parsers::iq::Iq;
use xmpp::parsers::message::Message;

const PUBSUB_NS: &str = "http://jabber.org/protocol/pubsub";
pub const OMEMO_NS: &str = "urn:xmpp:omemo:2";
pub const DEVICES_NODE: &str = "urn:xmpp:omemo:2:devices";
pub const BUNDLES_NODE: &str = "urn:xmpp:omemo:2:bundles";

pub fn device_list_fetch_iq(jid: &str, id: &str) -> Option<Iq> {
    let target = jid.parse::<Jid>().ok()?;
    let items = Element::builder("items", PUBSUB_NS)
        .attr("node".try_into().expect("static attribute"), DEVICES_NODE)
        .build();
    let payload = Element::builder("pubsub", PUBSUB_NS).append(items).build();
    Some(Iq::Get { from: None, to: Some(target), id: id.to_owned(), payload })
}

pub fn bundle_fetch_iq(jid: &str, device_id: u32, id: &str) -> Option<Iq> {
    let target = jid.parse::<Jid>().ok()?;
    let node = format!("{BUNDLES_NODE}:{device_id}");
    let items = Element::builder("items", PUBSUB_NS)
        .attr("node".try_into().expect("static attribute"), node)
        .build();
    let payload = Element::builder("pubsub", PUBSUB_NS).append(items).build();
    Some(Iq::Get { from: None, to: Some(target), id: id.to_owned(), payload })
}

pub fn publish_device_list_iq(jid: &str, device_id: u32, id: &str) -> Option<Iq> {
    let target = jid.parse::<Jid>().ok()?;
    let device = Element::builder("device", OMEMO_NS)
        .attr("id".try_into().expect("static attribute"), device_id.to_string())
        .build();
    let list = Element::builder("list", OMEMO_NS).append(device).build();
    Some(publish_iq(target, id, DEVICES_NODE, "current", list, Some("1")))
}

pub fn publish_bundle_iq(jid: &str, bundle: &Bundle, id: &str) -> Option<Iq> {
    let target = jid.parse::<Jid>().ok()?;
    let identity = Element::builder("identity", OMEMO_NS)
        .append(Element::builder("value", OMEMO_NS).append(hex::encode(&bundle.ik)).build())
        .build();
    let spk = Element::builder("signed-pre-key", OMEMO_NS)
        .append(Element::builder("value", OMEMO_NS).append(hex::encode(&bundle.spk)).build())
        .build();
    let payload = Element::builder("bundle", OMEMO_NS)
        .attr("device_id".try_into().expect("static attribute"), bundle.device_id.to_string())
        .append(identity)
        .append(spk)
        .build();
    let node = format!("{BUNDLES_NODE}:{}", bundle.device_id);
    Some(publish_iq(target, id, &node, "current", payload, Some("max")))
}

fn publish_iq(
    target: Jid,
    id: &str,
    node: &str,
    item_id: &str,
    payload: Element,
    max_items: Option<&str>,
) -> Iq {
    let item = Element::builder("item", PUBSUB_NS)
        .attr("id".try_into().expect("static attribute"), item_id)
        .append(payload)
        .build();
    let publish = Element::builder("publish", PUBSUB_NS)
        .attr("node".try_into().expect("static attribute"), node)
        .append(item)
        .build();
    let mut fields = Element::builder("x", "jabber:x:data")
        .attr("type".try_into().expect("static attribute"), "submit")
        .append(data_field("FORM_TYPE", "http://jabber.org/protocol/pubsub#publish-options", Some("hidden")));
    fields = fields.append(data_field("pubsub#access_model", "open", None));
    if let Some(max_items) = max_items {
        fields = fields.append(data_field("pubsub#max_items", max_items, None));
    }
    let publish_options = Element::builder("publish-options", PUBSUB_NS)
        .append(fields.build())
        .build();
    let pubsub = Element::builder("pubsub", PUBSUB_NS)
        .append(publish)
        .append(publish_options)
        .build();
    Iq::Set { from: None, to: Some(target), id: id.to_owned(), payload: pubsub }
}

fn data_field(name: &str, value: &str, field_type: Option<&str>) -> Element {
    let mut field = Element::builder("field", "jabber:x:data")
        .attr("var".try_into().expect("static attribute"), name);
    if let Some(field_type) = field_type {
        field = field.attr("type".try_into().expect("static attribute"), field_type);
    }
    field.append(Element::builder("value", "jabber:x:data").append(value).build()).build()
}

pub fn parse_device_list_payload(payload: &Element) -> Option<Vec<u32>> {
    let items = payload.get_child("items", PUBSUB_NS)?;
    let mut devices = Vec::new();
    for item in items.children().filter(|item| item.name() == "item" && item.ns() == PUBSUB_NS) {
        if let Some(list) = item.get_child("list", OMEMO_NS) {
            for device in list.children().filter(|device| device.name() == "device" && device.ns() == OMEMO_NS) {
                let id = device.attr("id")?.parse::<u32>().ok()?;
                devices.push(id);
            }
        }
    }
    if devices.is_empty() { None } else { Some(devices) }
}

pub fn parse_bundle_payload(payload: &Element, device_id: u32) -> Option<Bundle> {
    let items = payload.get_child("items", PUBSUB_NS)?;
    for item in items.children().filter(|item| item.name() == "item" && item.ns() == PUBSUB_NS) {
        if let Some(bundle) = item.get_child("bundle", OMEMO_NS) {
            let identity = bundle.get_child("identity", OMEMO_NS)?.text();
            let spk = bundle.get_child("signed-pre-key", OMEMO_NS)?.text();
            let ik = hex::decode(identity).ok()?;
            let spk = hex::decode(spk).ok()?;
            return Some(Bundle { device_id, ik, spk, opk: vec![] });
        }
    }
    None
}

pub fn encrypted_message_element(message: &EncryptedMessage, to: &str, id: &str) -> Option<Message> {
    let mut encrypted = Element::builder("encrypted", OMEMO_NS);
    let header = Element::builder("header", OMEMO_NS)
        .attr("sid".try_into().expect("static attribute"), message.header.sid.to_string());
    let mut header = header;
    for key in &message.header.keys {
        let key_element = Element::builder("key", OMEMO_NS)
            .attr("rid".try_into().expect("static attribute"), key.rid.to_string())
            .attr("kex".try_into().expect("static attribute"), key.kex.to_string())
            .append(STANDARD.encode(&key.data))
            .build();
        header = header.append(key_element);
    }
    let payload = Element::builder("payload", OMEMO_NS)
        .append(STANDARD.encode(&message.payload))
        .build();
    encrypted = encrypted.append(header.build()).append(payload);
    let stanza = Element::builder("message", "jabber:client")
        .attr("to".try_into().expect("static attribute"), to)
        .attr("id".try_into().expect("static attribute"), id)
        .append(encrypted.build())
        .build();
    Message::try_from(stanza).ok()
}

pub fn encrypted_payload(message: &Message) -> Option<EncryptedMessage> {
    let element = message.payloads.iter().find(|payload| payload.name() == "encrypted" && payload.ns() == OMEMO_NS)?;
    let header = element.get_child("header", OMEMO_NS)?;
    let sid = header.attr("sid")?.parse::<u32>().ok()?;
    let mut keys = Vec::new();
    for key in header.children().filter(|key| key.name() == "key" && key.ns() == OMEMO_NS) {
        let rid = key.attr("rid")?.parse::<u32>().ok()?;
        let data = STANDARD.decode(key.text()).ok()?;
        let kex = key.attr("kex").map(|value| value == "true").unwrap_or(false);
        keys.push(EncryptedKey { rid, data, kex });
    }
    let payload_text = element.get_child("payload", OMEMO_NS)?.text();
    let payload = STANDARD.decode(&payload_text).ok().unwrap_or_else(|| payload_text.into_bytes());
    Some(EncryptedMessage { header: EncryptedHeader { sid, keys }, payload })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_fetch_is_targeted_to_bare_jid() {
        let iq = device_list_fetch_iq("peer@example.org", "devices-1").unwrap();
        let Iq::Get { to, payload, .. } = iq else { panic!("expected get IQ") };
        assert_eq!(to.unwrap().to_string(), "peer@example.org");
        assert_eq!(payload.get_child("items", PUBSUB_NS).unwrap().attr("node"), Some(DEVICES_NODE));
    }

    #[test]
    fn publish_stanzas_include_open_access_and_form_type() {
        let iq = publish_device_list_iq("me@example.org", 7, "publish-1").unwrap();
        let Iq::Set { payload, .. } = iq else { panic!("expected set IQ") };
        let options = payload.get_child("publish-options", PUBSUB_NS).unwrap();
        assert!(options.get_child("x", "jabber:x:data").is_some());
    }

    #[test]
    fn publishes_omemo2_device_and_bundle_nodes() {
        let bundle = crate::omemo::Bundle {
            device_id: 7,
            ik: vec![0x11, 0x22, 0x33],
            spk: vec![0x44, 0x55, 0x66],
            opk: vec![],
        };
        let device_iq = publish_device_list_iq("me@example.org", 7, "device-publish").unwrap();
        let Iq::Set { payload: devices_payload, .. } = device_iq else { panic!("expected set IQ") };
        let publish = devices_payload.get_child("publish", PUBSUB_NS).unwrap();
        assert_eq!(publish.attr("node"), Some(DEVICES_NODE));
        let bundle_iq = publish_bundle_iq("me@example.org", &bundle, "bundle-publish").unwrap();
        let Iq::Set { payload: bundle_payload, .. } = bundle_iq else { panic!("expected set IQ") };
        let publish = bundle_payload.get_child("publish", PUBSUB_NS).unwrap();
        let expected_bundle_node = format!("{BUNDLES_NODE}:7");
        assert_eq!(publish.attr("node"), Some(expected_bundle_node.as_str()));
    }
}
