use std::collections::HashMap;

use crate::{config::Config, domain::AuthError};
use resend_rs::{types::CreateEmailBaseOptions, Resend};

pub struct Email {
    resend: Resend,
    to: String,
    subject: String,
}

impl Email {
    pub fn new(config: &Config, to: String, subject: String) -> Self {
        let resend = Resend::new(config.resend.as_str());
        Self {
            resend,
            to,
            subject,
        }
    }

    pub async fn send(
        &self,
        mut html: String,
        variables: HashMap<String, String>,
    ) -> Result<(), AuthError> {
        let base = env!("CARGO_MANIFEST_DIR");
        let lang = variables.get("lang").unwrap_or(&String::from("en")).clone();
        html = std::fs::read_to_string(format!(
            "{}/assets/html_email_templates/{}/{}.html",
            base, lang, html
        ))
        .unwrap_or_else(|_| html.clone());

        for (key, value) in variables.clone() {
            let placeholder = format!("{{{{{}}}}}", key);
            html = html.replace(&placeholder, &value);
        }

        let email = CreateEmailBaseOptions::new(
            "Lootopia<no-reply@wookiesrpeople2.dev>",
            vec![self.to.clone()],
            &self.subject,
        )
        .with_html(html.as_str());

        let _ = self
            .resend
            .emails
            .send(email)
            .await
            .map_err(|_| AuthError::Internal)?;

        Ok(())
    }
}
