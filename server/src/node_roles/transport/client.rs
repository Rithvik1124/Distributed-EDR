// node_roles/transport/client.rs

use reqwest::blocking::Client;
use serde::Serialize;
use crate::node_roles::get_server_ip;

pub struct ServerClient {
    client: Client,
    endpoint: String,
}

impl ServerClient {

    pub fn new(endpoint: &str) -> Self {
        let server_ip = get_server_ip();
        let endpoint = &format!("http://{}/telemetry-results", server_ip ) as &str;

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