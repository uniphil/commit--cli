// lkajslfkj not sure how to activate this only for the *crate name*
#![allow(non_snake_case)]

use anyhow::Context;
use git2::{Commit, Repository};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, SystemTime};
use structopt::StructOpt;
use httparse::{EMPTY_HEADER, Request, Result as HttpResult, Error::TooManyHeaders};
use keyring::{Entry, Error as KeyringError};
use oauth2::{
    AccessToken,
    AuthorizationCode,
    AuthUrl,
    basic::BasicTokenType,
    ClientId,
    CsrfToken,
    EmptyExtraTokenFields,
    PkceCodeChallenge,
    RedirectUrl,
    Scope,
    StandardTokenResponse,
    TokenResponse,
    TokenUrl,
    url::Url,
};
use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;
use reqwest::{StatusCode, header};


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
const LOCAL_AUTH_HOST: &str = "localhost";
const LOCAL_AUTH_PORT: u32 = 33205;


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
    fn from_token_response(token: StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>) -> StoredToken {
        StoredToken {
            v: TOKEN_STORE_VERSION.to_string(),
            access: token.access_token().to_owned(),
            expires: token.expires_in().map(|dt| (now() + dt).as_secs())
        }
    }
    fn to_bearer(&self) -> &String {
        if let Some(exp) = self.expires {
            if now().as_secs() >= exp {
                eprintln!("Access token has expired -- you'll probably need to log in.");
            }
        }
        self.access.secret()
    }
}


#[derive(Debug, Serialize)]
enum GitOrigin {
    #[serde(rename = "github")]
    Github {
        repo: String,
    },
}


impl GitOrigin {
    fn parse(remote: &str) -> Result<GitOrigin, anyhow::Error> {
        remote
            .strip_prefix("git@github.com:")
            .and_then(|r| r.strip_suffix(".git"))
            .map(|repo| GitOrigin::Github { repo: repo.to_owned() })
            .with_context(|| format!("Could not parse remote \"{:?}\" to an origin (only github ssh is recognized currently)", remote))
    }
}


fn not_found(stream: &mut TcpStream) -> Result<(), std::io::Error> {
    let response = "HTTP/1.1 404 NOT FOUND\r\n\r\n";
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}


#[derive(Debug)]
enum Heard<T> {
    Ya(T),
    Ohno(String),
}


fn handle_auth_redirect(req: Request) -> Heard<(String, String)> {
    let path = match (req.method, req.path) {
        (Some("GET"), Some(p)) if p.starts_with("/oauth/authorized") => p,
        (m, p) => {
            return Heard::Ohno(format!("Ignoring unexpected request: {:?} {:?}", m, p))
        },
    };
    let url = match Url::parse("http://x.y").unwrap().join(path) {
        Ok(u) => u,
        Err(e) => {
            return Heard::Ohno(format!("could not parse path at GET {:?}: {:?}", path, e))
        }
    };
    let (mut code, mut state) = (None, None);
    for (ref k, ref v) in url.query_pairs() {
        match k {
            Cow::Borrowed("code") => { code = Some(v.to_string()) },
            Cow::Borrowed("state") => { state = Some(v.to_string()) },
            _ => {},
        }
    }
    match (&code, &state) {
        (Some(c), Some(s)) => Heard::Ya((c.to_owned(), s.to_owned())),
        _ => Heard::Ohno(format!("could not find all params in query: code={:?} state={:?}", code, state)),
    }
}

fn handle_token_followup(req: Request) -> Heard<()> {
    match (req.method, req.path) {
        (Some("GET"), Some("/token-status")) => Heard::Ya(()),
        (m, p) => Heard::Ohno(format!("Ignoring unexpected request: {:?} {:?}", m, p))
    }
}


fn listen_for<T, F>(handler: F, status: &str, response: String, listener: &TcpListener) -> Result<T, std::io::Error>
    where F: Fn(Request) -> Heard<T> {
    // terrible terrible hacky lil local http server
    for s in listener.incoming() {
        let mut stream = s?;
        let mut buffer = [0; 1024];
        stream.read_exact(&mut buffer)?;

        let mut req = Request::new(&mut [EMPTY_HEADER; 0]);

        match req.parse(&buffer) {
            HttpResult::Ok(_) => {},
            HttpResult::Err(TooManyHeaders) => {}, // we allocated zero headers, so this is expected
            HttpResult::Err(e) => {
                eprintln!("Ignoring request that could not be parsed: {:?}", e);
                not_found(&mut stream)?;
                continue
            },
        };

        match handler(req) {
            Heard::Ya(stuff) => {
                let resp = format!("HTTP/1.1 {}\r\nContent-Length: {}\r\n\r\n{}", status, response.len(), response);
                stream.write_all(resp.as_bytes())?;
                stream.flush()?;
                return Ok(stuff)
            },
            Heard::Ohno(msg) => {
                eprintln!("{}", msg);
                not_found(&mut stream)?;
            },
        }
    }
    unreachable!()
}

fn oauth() -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>, anyhow::Error> {
    // bind early so we can bail if the port is not available
    let listener = TcpListener::bind(&format!("{}:{}", LOCAL_AUTH_HOST, LOCAL_AUTH_PORT))
        .unwrap_or_else(|e| panic!("Could not bind to port {} for oauth redirect listener: {:?}", LOCAL_AUTH_PORT, e));

    let client =
        BasicClient::new(
            ClientId::new("commit--cli".to_string()),
            None,
            AuthUrl::new(format!("{}/oauth/auth", COMMIT_BLOG_HOST)).expect("auth url"),
            Some(TokenUrl::new(format!("{}/oauth/token", COMMIT_BLOG_HOST)).expect("token url"))
        )
        .set_redirect_uri(RedirectUrl::new(format!("http://{}:{}/oauth/authorized", LOCAL_AUTH_HOST, LOCAL_AUTH_PORT))?);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("blog".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    println!("\nAuth URL ready: {}\n\nLaunching browser...", auth_url);
    match webbrowser::open(auth_url.as_str()) {
        Ok(_) => println!("Launched! Please complete the authorization in browser :)"),
        Err(e) => println!("Could not launch browser: {:?}\nVisit the URL above to complete authorization.", e),
    }

    println!("waiting for auth redirect...");
    let (code, state) = listen_for(handle_auth_redirect, "200 OK", include_str!("authorized.html").to_string(), &listener)?;

    assert_eq!(&state, csrf_token.secret(), "csrf check");

    let token =
        client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(pkce_verifier)
            .add_extra_param("client_id", "commit--cli")  // ??? seems like this wasn't sending??
            .request(http_client)?;

    listen_for(handle_token_followup, "200 OK", "got token".to_string(), &listener)?;
    Ok(token)
}


fn post(commit: Commit, origin: GitOrigin, token: StoredToken) -> Result<(), reqwest::Error> {
    let client = reqwest::blocking::Client::new();
    let resp = client.put(&format!("{}/api/blog/{}", COMMIT_BLOG_HOST, commit.id()))
        .header(header::USER_AGENT, "commit--cli hacky test version")
        .bearer_auth(token.to_bearer())
        .json(&origin)
        .send()?;

    match resp.status() {
        code if code.is_success() =>  {
            let data = resp.json::<HashMap<String, String>>().unwrap();
            println!("{:#?}", data);
        },
        StatusCode::BAD_REQUEST => {
            eprintln!("Failed to post: {:?}", resp.text());
        },
        otherwise => {
            panic!("Got unexpected non-success response status: {:?}", otherwise)
        }
    }
    Ok(())
}

fn unpost(commit: Commit, origin: GitOrigin, token: StoredToken) -> Result<(), reqwest::Error> {
    let client = reqwest::blocking::Client::new();
    let resp = client.delete(&format!("{}/api/blog/{}", COMMIT_BLOG_HOST, commit.id()))
        .header(header::USER_AGENT, "commit--cli hacky test version")
        .bearer_auth(token.to_bearer())
        .json(&origin)
        .send()?;

    match resp.status() {
        code if code.is_success() =>  {
            println!("ok, unposted.");
        },
        StatusCode::BAD_REQUEST => {
            eprintln!("Failed to unpost: {:?}", resp.text());
        },
        otherwise => {
            panic!("Got unexpected non-success response status: {:?}", otherwise)
        }
    }
    Ok(())
}

fn get_token(entry: Entry) -> StoredToken {
    let stored = match entry.get_password() {
        Ok(s) => s,
        Err(KeyringError::NoEntry) => panic!("commit--blog auth not found -- maybe log in first"),
        Err(e) => panic!("error getting token: {:?}", e),
    };
    serde_json::from_str(&stored).expect("parse existing token")
}


fn get_commit(repo: &Repository, git_ref: Option<String>) -> Result<Commit, git2::Error> {
    repo.revparse_single(&git_ref.unwrap_or_else(|| "HEAD".to_string()))
        .and_then(|obj| obj.peel_to_commit())
}


fn get_likely_origin(repo: &Repository) -> Option<GitOrigin> {
    let mut origin = None;
    for remote in repo.remotes().unwrap().iter() {
        let details = repo.find_remote(remote.unwrap()).unwrap();
        let url = details.url().unwrap();
        match GitOrigin::parse(url) {
            Ok(o) => { origin = Some(o) },
            Err(err) => eprintln!("ignoring origin: {:?}", err),
        }
    }
    origin
}


fn main() -> Result<(), anyhow::Error> {
    let entry = Entry::new("commit--blog", "auth");
    match Blog::from_args() {
        Blog::Login => {
            if let Ok(json_token) = entry.get_password() {
                let stored: StoredToken = serde_json::from_str(&json_token).expect("parses existing token");
                println!("tok: {:?}", stored);
                if let Some(exp) = stored.expires {
                    if now().as_secs() >= exp {
                        println!("oh no, access token might be expired");
                    }
                }
            } else {
                let token = oauth()?;
                let storable = StoredToken::from_token_response(token);
                let j = serde_json::to_string(&storable).expect("jsonify");
                entry.set_password(&j)?;
                println!("new access token saved.")
            }
        },
        Blog::Logout => {
            entry.delete_password()?;
            println!("access token deleted.")
        },
        Blog::Post { git_ref } => {
            let token = get_token(entry);
            let repo = Repository::discover(env::current_dir()?)?;
            let commit = get_commit(&repo, git_ref)?;
            let origin = get_likely_origin(&repo).expect("origin to be found");
            post(commit, origin, token)?
        },
        Blog::Unpost { git_ref } => {
            let token = get_token(entry);
            let repo = Repository::discover(env::current_dir()?)?;
            let commit = get_commit(&repo, git_ref)?;
            let origin = get_likely_origin(&repo).expect("origin to be found");
            unpost(commit, origin, token)?
        },
    }
    Ok(())
}
