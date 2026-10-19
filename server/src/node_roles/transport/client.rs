// node_roles/transport/client.rs

use reqwest::Client;
use serde::Serialize;
use crate::node_roles::get_server_ip;

pub struct ServerClient {
    client: Client,
    endpoint: String,
}

impl ServerClient {
    pub fn new() -> Self {
        let server_ip = get_server_ip();
        let endpoint = format!("http://{}:3000/telemetry-results", server_ip);

        Self {
            client: Client::new(),
            endpoint,
        }
    }

    pub async fn send_event<T: Serialize + ?Sized>(
        &self,
        event: &T,
    ) -> Result<(), reqwest::Error> {
        println!("Sending event to {}", self.endpoint);

        let response = self
            .client
            .post(&self.endpoint)
            .json(event)
            .send()
            .await?;

        println!(
            "I sent the event X687: HTTP {}",
            response.status()
        );

        Ok(())
    }
}