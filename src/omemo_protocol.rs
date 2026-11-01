use dziber_omemo::bundle::{Bundle, build_bundle_element_v0};
use dziber_omemo::device::{Device, build_device_list_element_v0};
use dziber_omemo::message::{EncryptedMessage, build_message_stanza};
use xmpp::jid::Jid;
use xmpp::minidom::Element;
use xmpp::parsers::iq::Iq;
use xmpp::parsers::message::Message;

const PUBSUB_NS: &str = "http://jabber.org/protocol/pubsub";
pub const OMEMO_NS: &str = dziber_omemo::NS_OMEMO_V0;
pub const DEVICES_NODE: &str = dziber_omemo::NS_OMEMO_V0_DEVICES;
pub const BUNDLES_NODE: &str = dziber_omemo::NS_OMEMO_V0_BUNDLES;

pub fn device_list_fetch_iq(jid: &str, id: &str) -> Option<Iq> {
    let target = jid.parse::<Jid>().ok()?;
    let items = Element::builder("items", PUBSUB_NS).attr("node".try_into().expect("static attribute"), DEVICES_NODE).build();
    let payload = Element::builder("pubsub", PUBSUB_NS).append(items).build();
    Some(Iq::Get { from: None, to: Some(target), id: id.to_owned(), payload })
}

pub fn bundle_fetch_iq(jid: &str, device_id: u32, id: &str) -> Option<Iq> {
    let target = jid.parse::<Jid>().ok()?;
    let node = format!("{BUNDLES_NODE}:{device_id}");
    let items = Element::builder("items", PUBSUB_NS).attr("node".try_into().expect("static attribute"), node).build();
    let payload = Element::builder("pubsub", PUBSUB_NS).append(items).build();
    Some(Iq::Get { from: None, to: Some(target), id: id.to_owned(), payload })
}

pub fn publish_device_list_iq(jid: &str, device_id: u32, id: &str) -> Option<Iq> {
    let target = jid.parse::<Jid>().ok()?;
    let devices = [Device { id: device_id, label: None, labelsig: None }];
    let payload = bridge_legacy_element(&build_device_list_element_v0(&devices))?;
    Some(publish_iq(target, id, DEVICES_NODE, "current", payload, Some("1")))
}

pub fn publish_bundle_iq(jid: &str, bundle: &Bundle, id: &str) -> Option<Iq> {
    let target = jid.parse::<Jid>().ok()?;
    let payload = bridge_legacy_element(&build_bundle_element_v0(bundle))?;
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
    let mut fields = Element::builder("x", "jabber:x:data").attr("type".try_into().expect("static attribute"), "submit")
        .append(data_field("FORM_TYPE", "http://jabber.org/protocol/pubsub#publish-options", Some("hidden")));
    fields = fields.append(data_field("pubsub#access_model", "open", None));
    if let Some(max_items) = max_items {
        fields = fields.append(data_field("pubsub#max_items", max_items, None));
    }
    let publish_options = Element::builder("publish-options", PUBSUB_NS).append(fields.build()).build();
    let pubsub = Element::builder("pubsub", PUBSUB_NS).append(publish).append(publish_options).build();
    Iq::Set { from: None, to: Some(target), id: id.to_owned(), payload: pubsub }
}

fn data_field(name: &str, value: &str, field_type: Option<&str>) -> Element {
    let mut field = Element::builder("field", "jabber:x:data").attr("var".try_into().expect("static attribute"), name);
    if let Some(field_type) = field_type { field = field.attr("type".try_into().expect("static attribute"), field_type); }
    field.append(Element::builder("value", "jabber:x:data").append(value).build()).build()
}

pub fn parse_device_list_payload(payload: &Element) -> Option<Vec<u32>> {
    let items = payload.get_child("items", PUBSUB_NS)?;
    items.children().filter(|item| item.name() == "item" && item.ns() == PUBSUB_NS)
        .flat_map(|item| item.children())
        .find_map(|element| {
            let legacy = bridge_to_legacy_element(&element)?;
            dziber_omemo::device::parse_device_list(&legacy)
                .map(|list| list.devices.into_iter().map(|device| device.id).collect())
        })
}

pub fn parse_bundle_payload(payload: &Element, device_id: u32) -> Option<Bundle> {
    let items = payload.get_child("items", PUBSUB_NS)?;
    for item in items.children().filter(|item| item.name() == "item" && item.ns() == PUBSUB_NS) {
        for element in item.children() {
            let Some(mut bundle) = dziber_omemo::bundle::parse_bundle(&bridge_to_legacy_element(&element)?) else { continue; };
            bundle.device_id = device_id;
            return Some(bundle);
        }
    }
    None
}

pub fn encrypted_message_element(message: &EncryptedMessage, to: &str, id: &str) -> Option<Message> {
    let stanza = build_message_stanza(to, message, id, None);
    let modern = bridge_legacy_element(&stanza)?;
    Message::try_from(modern).ok()
}

pub fn encrypted_payload(message: &Message) -> Option<dziber_omemo::message::EncryptedMessage> {
    let element = message.payloads.iter().find(|payload| payload.name() == "encrypted" && payload.ns() == OMEMO_NS)?;
    dziber_omemo::message::parse_encrypted_message(&bridge_to_legacy_element(element)?)
}

fn bridge_legacy_element(element: &legacy_minidom::Element) -> Option<Element> {
    let mut bytes = Vec::new();
    element.write_to(&mut bytes).ok()?;
    let xml = String::from_utf8(bytes).ok()?;
    xml.parse().ok()
}

fn bridge_to_legacy_element(element: &Element) -> Option<legacy_minidom::Element> {
    let mut bytes = Vec::new();
    element.write_to(&mut bytes).ok()?;
    let xml = String::from_utf8(bytes).ok()?;
    xml.parse().ok()
}

// dziber-omemo 0.0.3 depends on minidom 0.18 while xmpp-rs uses 0.19.
mod legacy_minidom {
    pub use ::minidom_legacy::Element;
}

#[cfg(test)]
mod tests {
    use super::*;
    use dziber_omemo::store::MemoryStore;

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
    fn publishes_conversations_legacy_device_and_bundle_nodes() {
        let manager = dziber_omemo::OmemoManager::generate(7, Box::new(MemoryStore::new()));
        let device_iq = publish_device_list_iq("me@example.org", 7, "device-publish").unwrap();
        let Iq::Set { payload: devices_payload, .. } = device_iq else { panic!("expected set IQ") };
        let publish = devices_payload.get_child("publish", PUBSUB_NS).unwrap();
        assert_eq!(publish.attr("node"), Some(dziber_omemo::NS_OMEMO_V0_DEVICES));
        let item = publish.get_child("item", PUBSUB_NS).unwrap();
        assert!(item.get_child("list", dziber_omemo::NS_OMEMO_V0).is_some());

        let bundle = manager.self_bundle().unwrap();
        let bundle_iq = publish_bundle_iq("me@example.org", &bundle, "bundle-publish").unwrap();
        let Iq::Set { payload: bundle_payload, .. } = bundle_iq else { panic!("expected set IQ") };
        let publish = bundle_payload.get_child("publish", PUBSUB_NS).unwrap();
        let expected_bundle_node = format!("{}:7", dziber_omemo::NS_OMEMO_V0_BUNDLES);
        assert_eq!(publish.attr("node"), Some(expected_bundle_node.as_str()));
        let item = publish.get_child("item", PUBSUB_NS).unwrap();
        assert!(item.get_child("bundle", dziber_omemo::NS_OMEMO_V0).is_some());
    }
}
