//! PEP (XEP-0163) plumbing: IQs with a timeout, publishing with open access, reading the
//! newest item of a node.

use std::time::Duration;

use futures::StreamExt;
use tokio_xmpp::jid::Jid;
use tokio_xmpp::minidom::rxml::NcName;
use tokio_xmpp::minidom::Element;
use tokio_xmpp::parsers::stanza_error::DefinedCondition;
use tokio_xmpp::{IqRequest, IqResponse};

use super::{Session, MAX_BACKLOG};

pub const PUBSUB: &str = "http://jabber.org/protocol/pubsub";
const PUBSUB_OWNER: &str = "http://jabber.org/protocol/pubsub#owner";
pub const DATA_FORMS: &str = "jabber:x:data";
const IQ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct IqError {
    pub condition: Option<DefinedCondition>,
    pub text: String,
}

/// An attribute name (minidom wants them validated).
pub fn n(name: &str) -> NcName {
    NcName::try_from(name).expect("valid attribute name")
}

/// A submitted data form with FORM_TYPE and one more field.
fn form(form_type: &str, var: &str, value: &str) -> Element {
    let field = |var: &str, value: &str| {
        Element::builder("field", DATA_FORMS).attr(n("var"), var).append(Element::builder("value", DATA_FORMS).append(value)).build()
    };
    Element::builder("x", DATA_FORMS).attr(n("type"), "submit").append(field("FORM_TYPE", form_type)).append(field(var, value)).build()
}

pub fn publish_open(node: &str, id: &str, item: Element) -> Element {
    Element::builder("pubsub", PUBSUB)
        .append(
            Element::builder("publish", PUBSUB)
                .attr(n("node"), node)
                .append(Element::builder("item", PUBSUB).attr(n("id"), id).append(item)),
        )
        .append(Element::builder("publish-options", PUBSUB).append(form(
            "http://jabber.org/protocol/pubsub#publish-options",
            "pubsub#access_model",
            "open",
        )))
        .build()
}

fn configure_open(node: &str) -> Element {
    Element::builder("pubsub", PUBSUB_OWNER)
        .append(Element::builder("configure", PUBSUB_OWNER).attr(n("node"), node).append(form(
            "http://jabber.org/protocol/pubsub#node_config",
            "pubsub#access_model",
            "open",
        )))
        .build()
}

pub fn items_request(node: &str) -> Element {
    Element::builder("pubsub", PUBSUB).append(Element::builder("items", PUBSUB).attr(n("node"), node).attr(n("max_items"), "1")).build()
}

/// The payload of the (single) item in an items result.
pub fn first_item(result: &Element) -> Option<&Element> {
    result.get_child("items", PUBSUB)?.get_child("item", PUBSUB)?.children().next()
}

/// The id of the (single) item in an items result.
pub fn first_item_id(result: &Element) -> Option<&str> {
    result.get_child("items", PUBSUB)?.get_child("item", PUBSUB)?.attr("id")
}

impl Session {
    pub(super) async fn iq(&mut self, to: Option<Jid>, req: IqRequest) -> Result<Option<Element>, IqError> {
        self.iq_within(to, req, IQ_TIMEOUT).await
    }

    /// Keeps reading the stream while waiting (into the backlog the main loop works off
    /// next): tokio-xmpp's queue holds only 16 events, and once it is full the answer
    /// itself would not get through until the timeout.
    pub(super) async fn iq_within(&mut self, to: Option<Jid>, req: IqRequest, timeout: Duration) -> Result<Option<Element>, IqError> {
        let token = self.client.send_iq(to, req).await;
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(token, deadline);
        let response = loop {
            tokio::select! {
                r = &mut token => break Some(r),
                _ = &mut deadline => break None,
                e = self.client.next(), if self.backlog.len() < MAX_BACKLOG => match e {
                    Some(e) => self.backlog.push_back(e),
                    None => break None,
                },
            }
        };
        match response {
            Some(Ok(IqResponse::Result(payload))) => Ok(payload),
            Some(Ok(IqResponse::Error(e))) => {
                let text = format!("{:?}", e.defined_condition);
                Err(IqError { condition: Some(e.defined_condition), text })
            }
            Some(Err(e)) => Err(IqError { condition: None, text: e.to_string() }),
            None => Err(IqError { condition: None, text: "no answer".into() }),
        }
    }

    /// Publishes with open access; if the node exists with another access model,
    /// reconfigures it and tries once more.
    pub(super) async fn publish(&mut self, node: &str, id: &str, item: Element) -> Result<(), String> {
        match self.iq(None, IqRequest::Set(publish_open(node, id, item.clone()))).await {
            Ok(_) => return Ok(()),
            Err(e) if e.condition == Some(DefinedCondition::Conflict) || e.text.contains("PreconditionNotMet") => {}
            Err(e) => return Err(e.text),
        }
        // XEP-0060 reports a mismatch as <conflict/> plus <precondition-not-met/>
        self.iq(None, IqRequest::Set(configure_open(node))).await.map_err(|e| format!("reconfiguring {node}: {}", e.text))?;
        self.iq(None, IqRequest::Set(publish_open(node, id, item))).await.map(drop).map_err(|e| e.text)
    }
}
