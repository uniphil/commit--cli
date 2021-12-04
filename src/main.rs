// lkajslfkj not sure how to activate this only for the *crate name*
#![allow(non_snake_case)]

use git2::Repository;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, SystemTime};
use structopt::StructOpt;
use httparse::{EMPTY_HEADER, Request, Result as HttpResult, Error::TooManyHeaders};
use keyring::Entry;
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


#[derive(Debug)]
struct Error {
}


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

const TOKEN_STORE_VERSION: &str = "0.1";
const HOST: &str = "localhost";
const PORT: u32 = 33205;


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
}


fn not_found(stream: &mut TcpStream) {
    let response = "HTTP/1.1 404 NOT FOUND\r\n\r\n";
    stream.write_all(response.as_bytes()).unwrap();
    stream.flush().unwrap();
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


fn listen_for<T, F>(handler: F, status: &str, response: String, listener: &TcpListener) -> Result<T, Error>
    where F: Fn(Request) -> Heard<T> {
    // terrible terrible hacky lil local http server
    for s in listener.incoming() {
        let mut stream = s.unwrap();
        let mut buffer = [0; 1024];
        stream.read_exact(&mut buffer).unwrap();

        let mut req = Request::new(&mut [EMPTY_HEADER; 0]);

        match req.parse(&buffer) {
            HttpResult::Ok(_) => {},
            HttpResult::Err(TooManyHeaders) => {}, // we allocated zero headers, so this is expected
            HttpResult::Err(e) => {
                eprintln!("Ignoring request that could not be parsed: {:?}", e);
                not_found(&mut stream);
                continue
            },
        };

        match handler(req) {
            Heard::Ya(stuff) => {
                let resp = format!("HTTP/1.1 {}\r\nContent-Length: {}\r\n\r\n{}", status, response.len(), response);
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
                return Ok(stuff)
            },
            Heard::Ohno(msg) => {
                eprintln!("{}", msg);
                not_found(&mut stream);
            },
        }
    }
    unreachable!()
}

fn oauth() -> StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType> {
    // bind early so we can bail if the port is not available
    let listener = TcpListener::bind(&format!("{}:{}", HOST, PORT))
        .unwrap_or_else(|e| panic!("Could not bind to port {} for oauth redirect listener: {:?}", PORT, e));

    let client =
        BasicClient::new(
            ClientId::new("commit--cli".to_string()),
            None,
            AuthUrl::new("http://localhost:5000/oauth/auth".to_string()).expect("auth url"),
            Some(TokenUrl::new("http://localhost:5000/oauth/token".to_string()).expect("token url"))
        )
        .set_redirect_uri(RedirectUrl::new(format!("http://{}:{}/oauth/authorized", HOST, PORT)).expect("redirect url"));

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
    let (code, state) = listen_for(handle_auth_redirect, "200 OK", include_str!("authorized.html").to_string(), &listener).unwrap();

    assert_eq!(&state, csrf_token.secret(), "csrf check");

    let token_result =
        client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(pkce_verifier)
            .add_extra_param("client_id", "commit--cli")  // ??? seems like this isn't sending??
            .request(http_client);

    match token_result {
        Ok(tok) => {
            listen_for(handle_token_followup, "200 OK", "got token".to_string(), &listener).unwrap();
            tok
        },
        Err(e) => {
            eprintln!("could not get token: {:?}", e);
            panic!("token")
        },
    }
}

fn main() {
    match Blog::from_args() {
        Blog::Login => {
            let entry = Entry::new("commit--blog", "auth");
            if let Ok(json_token) = entry.get_password() {
                let stored: StoredToken = serde_json::from_str(&json_token).expect("parses existing token");
                println!("tok: {:?}", stored);
                if let Some(exp) = stored.expires {
                    if now().as_secs() >= exp {
                        println!("oh no, access token might be expired");
                    }
                }
            } else {
                let token = oauth();
                let storable = StoredToken::from_token_response(token);
                let j = serde_json::to_string(&storable).expect("jsonify");
                match entry.set_password(&j) {
                    Ok(()) => println!("ya, new set"),
                    Err(err) => eprintln!("naaa setting: {:?}", err),
                }
            }
        },
        Blog::Logout => {
            let entry = Entry::new("commit--blog", "auth");
            match entry.delete_password() {
                Ok(()) => println!("ok password deleted"),
                Err(err) => eprintln!("error deleting pw: {:?}", err),
            }
        },
        Blog::Post { git_ref } => {
            let repo = match Repository::discover(env::current_dir().unwrap()) {
                Ok(repo) => {
                    println!("sweet, repo state: {:?}", repo.state());
                    repo
                },
                Err(e) => {
                    panic!("booo. error opening current git repo: {:?}", e);
                },
            };
            let obj = repo.revparse_single(&git_ref.unwrap_or("HEAD".to_string())).expect("to find the git fref");
            println!("found obj: {:?}", obj);
            for remote in repo.remotes().unwrap().iter() {
                println!("found remote: {:?}", remote);
                let details = repo.find_remote(remote.unwrap()).unwrap();
                println!("\tremote details: {:?}", details.url());
            }
            println!("remotename {:?}", repo.branch_upstream_name("refs/heads/main").unwrap().as_str());
            // eprintln!("todo: command for post. git ref: {:?}", git_ref);
            unimplemented!()
        },
        Blog::Unpost { git_ref } => {
            eprintln!("todo: command for unpost. git ref: {:?}", git_ref);
            unimplemented!()
        },
    }
}
