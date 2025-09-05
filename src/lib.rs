pub mod args;
pub mod auth;
pub mod config;
pub mod health;
pub mod protocol;
pub mod websocket_server;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = config::Config::default();
        assert_eq!(config.server.port, 10112);
        assert_eq!(config.health.port, 9090);
        assert!(config.health.enabled);
    }

    #[test]
    fn test_protocol_serialisation() {
        use protocol::{ClientMessage, FileInfo};

        // Test ListRequest message
        let msg = ClientMessage::ListRequest;
        let json = serde_json::to_string(&msg).unwrap();
        let deserialised: ClientMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(deserialised, ClientMessage::ListRequest));

        // Test FileInfo
        let file_info = FileInfo {
            name: "test.hecate".to_string(),
            size: 1024,
            created: "2024-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&file_info).unwrap();
        let deserialised: FileInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialised.name, file_info.name);
        assert_eq!(deserialised.size, file_info.size);
    }

    #[tokio::test]
    async fn test_auth_manager_creation() {
        use argon2::password_hash::{SaltString, rand_core::OsRng};
        use argon2::{Argon2, PasswordHasher};
        use auth::{AuthManager, ClientCredentials, ClientPermissions};
        use tempfile::tempdir;
        use tokio::fs;

        // Create a test config file with auth
        let dir = tempdir().unwrap();
        let auth_file = dir.path().join("auth.json");

        // Generate a proper hash for the test password
        let password = "test_password";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap();

        let clients = vec![ClientCredentials {
            client_id: "test_client".to_string(),
            key_hash: password_hash.to_string(),
            permissions: ClientPermissions::default(),
        }];

        let json = serde_json::to_string_pretty(&clients).unwrap();
        fs::write(&auth_file, json).await.unwrap();

        // Test creating with config
        let manager = AuthManager::new(Some(auth_file.to_str().unwrap().to_string()))
            .await
            .unwrap();

        // Authentication now requires client_id and key
        let perms = manager.authenticate("test_client", password).await.unwrap();
        assert!(perms.is_some());

        let perms = manager
            .authenticate("test_client", "wrong_password")
            .await
            .unwrap();
        assert!(perms.is_none());
    }

    #[test]
    fn test_config_serialisation() {
        let config = config::Config::default();
        let toml_str = toml::to_string(&config).unwrap();
        assert!(toml_str.contains("port"));

        let deserialised: config::Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(deserialised.server.port, config.server.port);
    }
}
