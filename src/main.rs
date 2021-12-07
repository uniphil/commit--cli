// lkajslfkj not sure how to activate this only for the *crate name*
#![allow(non_snake_case)]

use anyhow::Context;
use git2::{Commit, Repository};
use httparse::Request;
use keyring::{Entry, Error as KeyringError};
use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;
use oauth2::{
    basic::BasicTokenType, url::Url, AccessToken, AuthUrl, AuthorizationCode, ClientId, CsrfToken,
    EmptyExtraTokenFields, PkceCodeChallenge, RedirectUrl, Scope, StandardTokenResponse,
    TokenResponse, TokenUrl,
};
use reqwest::{header, StatusCode};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::env;

use std::time::{Duration, SystemTime};
use structopt::StructOpt;

mod local_listener;

#[derive(Debug, StructOpt)]
#[structopt(name = "commit--blog")]
enum Blog {
    Login,
    Logout,
    Post {
        /// A reference to identify the commit, like its hash or a tag.
        /// Defaults to the latest commit on the current branch.
        #[structopt(name = "ref")]
        git_ref: Option<String>,
    },
    Unpost {
        /// A reference to identify the commit, like its hash or a tag.
        /// Defaults to the latest commit on the current branch.
        #[structopt(name = "ref")]
        git_ref: Option<String>,
    },
}

const COMMIT_BLOG_HOST: &str = "http://localhost:5000";
const TOKEN_STORE_VERSION: &str = "0.1";
const LOCAL_AUTH_PORT: u16 = 33205;

fn now() -> Duration {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("now is after unix epoch")
}

#[derive(Serialize, Deserialize, Debug)]
struct StoredToken {
    v: String,
    access: AccessToken, // access token
    #[serde(skip_serializing_if = "Option::is_none")]
    expires: Option<u64>, // timestamp
}

impl StoredToken {
    fn from_token_response(
        token: StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    ) -> StoredToken {
        StoredToken {
            v: TOKEN_STORE_VERSION.to_string(),
            access: token.access_token().to_owned(),
            expires: token.expires_in().map(|dt| (now() + dt).as_secs()),
        }
    }
    fn to_bearer(&self) -> &String {
        self.access.secret()
    }
    fn info(&self) -> String {
        let mut details = format!("commit--cli stored token v{}", self.v);
        if let Some(exp) = self.expires {
            details += &format!(", expiring in {} seconds", exp - now().as_secs())
        }
        details
    }
}

#[derive(Debug, Serialize)]
enum GitOrigin {
    #[serde(rename = "github")]
    Github { repo: String },
}

impl GitOrigin {
    fn parse(remote: &str) -> Result<GitOrigin, anyhow::Error> {
        remote
            .strip_prefix("git@github.com:")
            .and_then(|r| r.strip_suffix(".git"))
            .map(|repo| GitOrigin::Github { repo: repo.to_owned() })
            .with_context(|| format!("Could not parse remote \"{}\" to an origin (only github ssh is recognized currently)", remote))
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

fn oauth() -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>, anyhow::Error> {
    // bind early so we can bail if the port is not available
    let ll = local_listener::LocalListener::new(LOCAL_AUTH_PORT)?;

    let client = BasicClient::new(
        ClientId::new("commit--cli".to_string()),
        None,
        AuthUrl::new(format!("{}/oauth/auth", COMMIT_BLOG_HOST)).expect("auth url"),
        Some(TokenUrl::new(format!("{}/oauth/token", COMMIT_BLOG_HOST)).expect("token url")),
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

fn post(commit: Commit, origin: GitOrigin, token: StoredToken) -> Result<(), reqwest::Error> {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .put(&format!("{}/api/blog/{}", COMMIT_BLOG_HOST, commit.id()))
        .header(header::USER_AGENT, "commit--cli hacky test version")
        .bearer_auth(token.to_bearer())
        .json(&origin)
        .send()?;

    match resp.status() {
        code if code.is_success() => {
            let data = resp.json::<HashMap<String, String>>().unwrap();
            println!("{:#?}", data);
        }
        StatusCode::BAD_REQUEST => {
            eprintln!("Failed to post: {:?}", resp.text()?);
        }
        otherwise => {
            panic!(
                "Got unexpected non-success response status: {:?}",
                otherwise
            )
        }
    }
    Ok(())
}

fn unpost(commit: Commit, origin: GitOrigin, token: StoredToken) -> Result<(), reqwest::Error> {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .delete(&format!("{}/api/blog/{}", COMMIT_BLOG_HOST, commit.id()))
        .header(header::USER_AGENT, "commit--cli hacky test version")
        .bearer_auth(token.to_bearer())
        .json(&origin)
        .send()?;

    match resp.status() {
        code if code.is_success() => {
            println!("ok, unposted.");
        }
        StatusCode::BAD_REQUEST => {
            eprintln!("Failed to unpost: {:?}", resp.text());
        }
        otherwise => {
            panic!(
                "Got unexpected non-success response status: {:?}",
                otherwise
            )
        }
    }
    Ok(())
}

fn get_token(entry: &Entry) -> Result<Option<StoredToken>, anyhow::Error> {
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

fn get_commit(repo: &Repository, git_ref: Option<String>) -> Result<Commit, git2::Error> {
    repo.revparse_single(&git_ref.unwrap_or_else(|| "HEAD".to_string()))
        .and_then(|obj| obj.peel_to_commit())
}

fn get_likely_origin(repo: &Repository) -> Result<GitOrigin, anyhow::Error> {
    let mut origin = None;
    for remote in repo.remotes()?.iter() {
        let details = repo.find_remote(remote.unwrap())?;
        let url = details.url().unwrap();
        match (GitOrigin::parse(url), &origin) {
            (Ok(o), None) => origin = Some(o),
            (Ok(o), Some(_)) => {
                eprintln!("Warning: multiple origins found. This is not handled yet -- using first found: {:?}", o);
            }
            (Err(e), _) => {
                eprintln!(
                    "Warning: ignorning unrecognized origin for url \"{}\": {:?}",
                    url, e
                );
            }
        }
        if let Ok(o) = GitOrigin::parse(url) {
            origin = Some(o);
        }
    }
    origin.context("No recognized git origin was found")
}

fn main() -> Result<(), anyhow::Error> {
    let entry = Entry::new("commit--blog", "auth");
    match Blog::from_args() {
        Blog::Login => {
            if let Some(token) = get_token(&entry)? {
                println!("Already logged in: found {}", token.info());
            } else {
                let raw_auth = oauth()?;
                let token = StoredToken::from_token_response(raw_auth);
                let s = serde_json::to_string(&token)?;
                entry.set_password(&s)?;
                println!("Access token saved.")
            }
        }
        Blog::Logout => {
            // TODO: send a request to revoke the token too
            entry.delete_password()?;
            println!("access token deleted.")
        }
        Blog::Post { git_ref } => {
            let token = get_token(&entry)?.context("Log in to post")?;
            let repo = Repository::discover(env::current_dir()?)?;
            let commit = get_commit(&repo, git_ref)?;
            let origin = get_likely_origin(&repo)?;
            post(commit, origin, token)?
        }
        Blog::Unpost { git_ref } => {
            let token = get_token(&entry)?.context("Log in to unpost")?;
            let repo = Repository::discover(env::current_dir()?)?;
            let commit = get_commit(&repo, git_ref)?;
            let origin = get_likely_origin(&repo)?;
            unpost(commit, origin, token)?
        }
    }
    Ok(())
}
