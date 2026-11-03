use serde::{Deserialize, Serialize};
use reqwest::Client;
use tracing::{info, warn, error};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerNode {
    pub node_id: String,
    pub address: String, // e.g., "http://192.168.1.50:8445"
    pub current_temp: f32,
    pub available: bool,
}

pub struct MeshClusterManager {
    local_node_id: String,
    peers: Vec<PeerNode>,
    client: Client,
}

impl MeshClusterManager {
    pub fn new(node_id: &str) -> Self {
        Self {
            local_node_id: node_id.to_string(),
            peers: Vec::new(),
            client: Client::new(),
        }
    }

    pub fn register_peer(&mut self, peer: PeerNode) {
        self.peers.retain(|p| p.node_id != peer.node_id);
        info!(node_id = %peer.node_id, address = %peer.address, "Registered new mesh peer.");
        self.peers.push(peer);
    }

    /// Selects the coolest available peer node in the mesh for offloading
    pub async fn route_to_mesh(&self, directive: &str, context_id: &str) -> Result<serde_json::Value, String> {
        let optimal_peer = self.peers.iter()
            .filter(|p| p.available && p.current_temp < 80.0)
            .min_by(|a, b| a.current_temp.partial_cmp(&b.current_temp).unwrap());

        if let Some(peer) = optimal_peer {
            let endpoint = format!("{}/api/v1/neuralbrain/execute", peer.address);
            info!(target_node = %peer.node_id, temp = peer.current_temp, "Offloading workload across mesh cluster.");

            let payload = serde_json::json!({
                "directive": directive,
                "context_id": context_id,
                "parameters": {}
            });

            let res = self.client.post(&endpoint)
                .json(&payload)
                .send()
                .await
                .map_err(|e| format!("Mesh routing network error: {}", e))?;

            if res.status().is_success() {
                let json_res = res.json::<serde_json::Value>().await
                    .map_err(|e| format!("Failed to parse mesh response: {}", e))?;
                return Ok(json_res);
            } else {
                return Err(format!("Mesh peer returned non-success status: {}", res.status()));
            }
        }

        Err("No available cooler nodes found in the mesh cluster.".to_string())
    }
}

