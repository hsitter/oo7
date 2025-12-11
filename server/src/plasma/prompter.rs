// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Harald Sitter <sitter@kde.org>

use oo7::{ashpd::WindowIdentifierType, dbus::ServiceError};
use serde::{Deserialize, Serialize};
use zbus::{object_server::SignalEmitter, zvariant::{
    self, ObjectPath, OwnedObjectPath, Type,
}};

use crate::{
    error::custom_service_error,
    prompt::{Prompt, PromptRole},
    service::Service,
};

#[derive(Deserialize, Serialize, Debug, Type)]
#[serde(rename_all = "lowercase")]
#[zvariant(signature = "s")]
pub enum Reply {
    Accepted,
    Rejected,
}

#[derive(Deserialize, Serialize, Debug, Type)]
#[serde(rename_all = "lowercase")]
#[zvariant(signature = "s")]
pub enum PromptType {
    Confirm,
    Password,
}

#[zbus::proxy(
    default_service = "org.kde.secretprompter",
    interface = "org.kde.secretprompter",
    default_path = "/SecretPrompter",
    gen_blocking = false
)]
pub trait PlasmaPrompter {
    // fn Prompt(&self, request: &ObjectPath<'_>, window_id: &str, title: &str, prompt: &str, type_: PromptType) -> Result<(), ServiceError>;
    fn UnlockCollectionPrompt(&self, request: &ObjectPath<'_>, window_id: &str, activation_token: &str, collection_name: &str) -> Result<(), ServiceError>;
    fn CreateCollectionPrompt(&self, request: &ObjectPath<'_>, window_id: &str, activation_token: &str, collection_name: &str) -> Result<(), ServiceError>;
}

#[derive(Debug, Clone)]
pub struct PlasmaPrompterCallback {
    service: Service,
    window_id: String,
    prompt_path: OwnedObjectPath,
    path: OwnedObjectPath,
}

#[zbus::interface(name = "org.kde.secretprompter.request")]
impl PlasmaPrompterCallback {
    pub async fn result(
        &self,
        type_: Reply,
        reply: &str,
    ) -> Result<(), ServiceError> {
        let prompt_path = &self.prompt_path;
        let Some(prompt) = self.service.prompt(prompt_path).await else {
            return Err(ServiceError::NoSuchObject(format!(
                "Prompt '{prompt_path}' does not exist."
            )));
        };

        match type_ {
            Reply::Accepted => {
                tracing::debug!("User accepted the prompt.");
                self.on_reply(&prompt, reply).await?;
            }
            Reply::Rejected => {
                tracing::debug!("User rejected the prompt.");
                self.dismiss().await?;
            }
        }

        Ok(())
    }

    #[zbus(signal)]
    pub async fn cancel(signal_emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
}

impl PlasmaPrompterCallback {
    pub async fn new(
        window_id: String,
        service: Service,
        prompt_path: OwnedObjectPath,
    ) -> Result<Self, oo7::crypto::Error> {
        let index = service.prompt_index().await;
        Ok(Self {
            path: OwnedObjectPath::try_from(format!("/org/plasma/keyring/Prompt/p{index}")).unwrap(),
            service,
            prompt_path,
            window_id,
        })
    }

    pub fn path(&self) -> &ObjectPath<'_> {
        &self.path
    }

    // TODO: this is largely duplicated from the gnome prompter. should be shared somehow. not sure how.
    async fn on_reply(&self, prompt: &Prompt, reply: &str) -> Result<(), ServiceError> {
        let prompter = PlasmaPrompterProxy::new(self.service.connection()).await?;

        // Handle each role differently based on what validation/preparation is needed
        match prompt.role() {
            PromptRole::Unlock => {
                let secret = oo7::Secret::from(reply);

                // Get the collection to validate the secret
                let collection = prompt.collection().expect("Unlock requires a collection");
                let label = prompt.label();

                // Validate the secret using the already-open keyring
                let keyring_guard = collection.keyring.read().await;
                let is_valid = keyring_guard
                    .as_ref()
                    .unwrap()
                    .validate_secret(&secret)
                    .await
                    .map_err(|err| {
                        custom_service_error(&format!(
                            "Failed to validate secret for {label} keyring: {err}."
                        ))
                    })?;
                drop(keyring_guard);

                if is_valid {
                    tracing::debug!("Keyring secret matches for {label}.");

                    let Some(action) = prompt.take_action().await else {
                        return Err(custom_service_error(
                            "Prompt action was already executed or not set",
                        ));
                    };

                    let result_value = action.execute(secret).await?;

                    let prompt_path = OwnedObjectPath::from(prompt.path().clone());
                    let signal_emitter = self.service.signal_emitter(prompt_path)?;
                    tokio::spawn(async move {
                        tracing::debug!("Unlock prompt completed.");
                        let _ = Prompt::completed(&signal_emitter, false, result_value).await;
                    });
                    Ok(())
                } else {
                    tracing::error!("Keyring {label} failed to unlock, incorrect secret.");

                    let path = self.path.clone();
                    let window_id = self.window_id.clone();
                    let collection_name = prompt.label().to_string();
                    tokio::spawn(async move {
                        prompter
                            .UnlockCollectionPrompt(
                                &path,
                                window_id.as_str(),
                                "",
                                collection_name.as_str(),
                            )
                            .await
                    });

                    Ok(())
                }
            }
            PromptRole::CreateCollection => {
                let secret = oo7::Secret::from(reply);

                let Some(action) = prompt.take_action().await else {
                    return Err(custom_service_error(
                        "Prompt action was already executed or not set",
                    ));
                };

                // Execute the collection creation action with the secret
                match action.execute(secret).await {
                    Ok(collection_path_value) => {
                        tracing::info!("CreateCollection action completed successfully");

                        let signal_emitter =
                            self.service.signal_emitter(prompt.path().to_owned())?;

                        tokio::spawn(async move {
                            tracing::debug!("CreateCollection prompt completed.");
                            let _ =
                                Prompt::completed(&signal_emitter, false, collection_path_value)
                                    .await;
                        });
                        Ok(())
                    }
                    Err(err) => Err(custom_service_error(&format!(
                        "Failed to create collection: {err}."
                    ))),
                }
            }
        }
    }

    async fn dismiss(&self) -> Result<(), ServiceError> {
        let signal_emitter = self.service.signal_emitter(self.prompt_path.clone())?;
        let result = zvariant::Value::new::<Vec<OwnedObjectPath>>(vec![])
            .try_into_owned()
            .unwrap();
        tokio::spawn(async move { Prompt::completed(&signal_emitter, true, result).await });
        Ok(())
    }
}
