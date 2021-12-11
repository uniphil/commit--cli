#![deny(non_snake_case)]

use crate::local_listener;
use anyhow::Context;
use httparse::Request;
use keyring::{Entry, Error as KeyringError};
use oauth2::basic::BasicClient;
use oauth2::ureq::{http_client, Error as O2UreqError};
use oauth2::{
    basic::BasicTokenType, url::Url, AccessToken, AuthUrl, AuthorizationCode, ClientId, CsrfToken,
    EmptyExtraTokenFields, PkceCodeChallenge, RedirectUrl, RequestTokenError, RevocationUrl, Scope,
    StandardRevocableToken, StandardTokenResponse, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::time::{Duration, SystemTime};

const LOCAL_AUTH_PORT: u16 = 33205;
const TOKEN_STORE_VERSION: &str = "0.1";

fn now() -> Duration {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("now is after unix epoch")
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StoredToken {
    v: String,
    access: AccessToken, // access token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>, // timestamp
}

impl StoredToken {
    pub fn from_token_response(
        token: StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    ) -> StoredToken {
        StoredToken {
            v: TOKEN_STORE_VERSION.to_string(),
            access: token.access_token().to_owned(),
            expires: token.expires_in().map(|dt| (now() + dt).as_secs()),
        }
    }
    pub fn to_bearer(&self) -> &String {
        self.access.secret()
    }
    pub fn info(&self) -> String {
        let mut details = format!("commit--cli stored token v{}", self.v);
        if let Some(exp) = self.expires {
            details += &format!(", expiring in {} seconds", exp - now().as_secs())
        }
        details
    }
}

fn for_auth_redirect(req: &Request) -> Option<(String, String)> {
    let path = match (req.method, req.path) {
        (Some("GET"), Some(p)) if p.starts_with("/oauth/authorized") => p,
        _ => return None,
    };
    let url = match Url::parse("http://x.y").unwrap().join(path) {
        Ok(u) => u,
        Err(_) => return None,
    };
    let (mut code, mut state) = (None, None);
    for (ref k, ref v) in url.query_pairs() {
        match k {
            Cow::Borrowed("code") => code = Some(v.to_string()),
            Cow::Borrowed("state") => state = Some(v.to_string()),
            _ => {}
        }
    }
    match (&code, &state) {
        (Some(c), Some(s)) => Some((c.to_owned(), s.to_owned())),
        _ => {
            eprintln!(
                "could not find all params in query: code={:?} state={:?}",
                code, state
            );
            None
        }
    }
}

fn for_token_followup(req: &Request) -> Option<()> {
    match (req.method, req.path) {
        (Some("GET"), Some("/token-status")) => Some(()),
        _ => None,
    }
}

pub fn oauth(
    blog_host: &str,
) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>, anyhow::Error> {
    // bind early so we can bail if the port is not available
    let ll = local_listener::LocalListener::new(LOCAL_AUTH_PORT)?;

    let client = BasicClient::new(
        ClientId::new("commit--cli".to_string()),
        None,
        AuthUrl::new(format!("{}/oauth/auth", blog_host))?,
        Some(TokenUrl::new(format!("{}/oauth/token", blog_host))?),
    )
    .set_redirect_uri(RedirectUrl::new(format!(
        "http://{}/oauth/authorized",
        ll.addr()?
    ))?);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("blog".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    println!("\nAuth URL ready: {}\n\nLaunching browser...", auth_url);
    match webbrowser::open(auth_url.as_str()) {
        Ok(_) => println!("Launched! Please complete the authorization in browser :)"),
        Err(e) => println!(
            "Could not launch browser: {:?}\nVisit the URL above to complete authorization.",
            e
        ),
    }

    println!("waiting for auth redirect...");

    let (ll, (code, state)) = ll.listen(for_auth_redirect)?;

    if &state != csrf_token.secret() {
        ll.reply("400 BAD REQUESTS", "400 bad request")?;
        anyhow::bail!("CSRF check failed during token authentication.")
    }

    let ll = ll.reply("200 OK", include_str!("authorized.html"))?;

    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .add_extra_param("client_id", "commit--cli") // ??? seems like this wasn't sending??
        .request(http_client)?;

    ll.listen(for_token_followup)?
        .0
        .reply("200 OK", "got token")?;

    Ok(token)
}

pub fn get_token(entry: &Entry) -> Result<Option<StoredToken>, anyhow::Error> {
    let token: StoredToken = match entry.get_password() {
        Ok(s) => serde_json::from_str(&s)?,
        Err(KeyringError::NoEntry) => return Ok(None),
        Err(e) => anyhow::bail!(e),
    };
    if let Some(exp) = token.expires {
        if now().as_secs() > exp {
            return None
                .context("Saved access token has expired, you'll need to log in for new one.");
        }
    }
    Ok(Some(token))
}

pub fn revoke(token: StoredToken, blog_host: &str) -> Result<bool, anyhow::Error> {
    let token = StandardRevocableToken::AccessToken(token.access);

    let client = BasicClient::new(
        ClientId::new("commit--cli".to_string()),
        None,
        AuthUrl::new(format!("{}/oauth/auth", blog_host)).expect("auth url"),
        Some(TokenUrl::new(format!("{}/oauth/token", blog_host))?),
    )
    .set_revocation_uri(RevocationUrl::new(format!("{}/oauth/revoke", blog_host))?);

    #[cfg(feature = "insecure")]
    let revoker = client.revoke_token_with_unchecked_url(token)?;

    #[cfg(not(feature = "insecure"))]
    let revoker = client.revoke_token(token)?;

    let resp = revoker
        .add_extra_param("client_id", "commit--cli") // ??? seems like this wasn't sending??
        .request(http_client);

    if let Err(RequestTokenError::Request(O2UreqError::Ureq(ref e))) = resp {
        if let ureq::Error::Status(404, _) = **e {
            eprintln!("Info: 404 token not found on server when trying to revoke.");
            return Ok(false);
        }
    }
    resp?;
    Ok(true)
}
