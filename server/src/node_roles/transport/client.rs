// node_roles/transport/client.rs

use reqwest::blocking::Client;
use serde::Serialize;

pub struct ServerClient {
    client: Client,
    endpoint: String,
}

impl ServerClient {
    pub fn new(endpoint: &str) -> Self {
        Self {
            client: Client::new(),
            endpoint: endpoint.to_string(),
        }
    }

    pub fn send_event<T: Serialize>(&self, event: &T) {
        let _ = self.client
            .post(&self.endpoint)
            .json(event)
            .send();
    }
}