use std::sync::Arc;

use anyhow::{Context, Result};

use crate::{BoxStream, OutboundManager, Session};

pub struct Router {
    outbounds: Arc<OutboundManager>,
    final_outbound: String,
}

impl Router {
    pub fn new(outbounds: Arc<OutboundManager>, final_outbound: impl Into<String>) -> Self {
        Self {
            outbounds,
            final_outbound: final_outbound.into(),
        }
    }

    pub async fn connect(&self, session: &mut Session) -> Result<BoxStream> {
        let tag = session
            .outbound
            .clone()
            .unwrap_or_else(|| self.final_outbound.clone());
        let outbound = self
            .outbounds
            .get(&tag)
            .await
            .with_context(|| format!("route outbound not found: {tag}"))?;
        session.outbound = Some(tag);
        outbound.connect(session).await
    }

    pub async fn relay(
        &self,
        session: Session,
        mut inbound: BoxStream,
        mut outbound: BoxStream,
    ) -> Result<()> {
        tracing::info!(
            inbound = %session.inbound,
            outbound = ?session.outbound,
            destination = %session.destination,
            user = ?session.user,
            "routing TCP connection"
        );
        tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
        Ok(())
    }

    pub async fn route(&self, mut session: Session, inbound: BoxStream) -> Result<()> {
        let outbound = self.connect(&mut session).await?;
        self.relay(session, inbound, outbound).await
    }
}
