// lkajslfkj not sure how to activate this only for the *crate name*
#![allow(non_snake_case)]

use serde::{Deserialize, Serialize};

use std::borrow::Cow;
use std::io::{Read, Write};
use std::net::TcpListener;
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
use webbrowser;


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


fn listen_for_things(listener: TcpListener) -> (String, String) {
    // terrible terrible hacky lil local http server
    for s in listener.incoming() {
        let mut stream = s.unwrap();
        let mut buffer = [0; 1024];
        stream.read(&mut buffer).unwrap();

        let mut req = Request::new(&mut [EMPTY_HEADER; 0]);

        'parse: loop {
            match req.parse(&buffer) {
                HttpResult::Err(TooManyHeaders) => {},
                _ => break 'parse,
            };
            if req.method != Some("GET") {
                eprintln!("ignoring non-GET request {:?}", req);
                break 'parse
            }
            let path = match req.path {
                Some(p) if p.starts_with("/oauth/authorized") => p,
                p => {
                    eprintln!("ignoring request at {:?}", p);
                    break 'parse
                },
            };
            let url = match Url::parse("http://x.y").unwrap().join(path) {
                Ok(u) => u,
                Err(e) => {
                    eprintln!("could not parse path at GET {:?}: {:?}", path, e);
                    break 'parse
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
                (Some(c), Some(s)) => {
                    let page = include_str!("authorized.html");
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", page.len(), page);
                    stream.write(response.as_bytes()).unwrap();
                    stream.flush().unwrap();
                    return (c.to_owned(), s.to_owned())
                },
                _ => {
                    eprintln!("could not find all params in query: code={:?} state={:?}", code, state);
                    break 'parse
                }
            }
        }

        let response = "HTTP/1.1 200 OK\r\n\r\n";
        stream.write(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    }
    unreachable!()
}

fn oauth() -> StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType> {
    // bind early so we can bail if the port is not available
    let listener = TcpListener::bind(&format!("{}:{}", HOST, PORT))
        .expect(&format!("Could not bind to port {} for oauth redirect listener", PORT));

    let client =
        BasicClient::new(
            ClientId::new("commit--cli".to_string()),
            None,
            AuthUrl::new("http://localhost:5000/oauth/auth".to_string()).expect("auth url"),
            Some(TokenUrl::new("http://localhost:5000/oauth/token".to_string()).expect("token url"))
        )
        .set_redirect_uri(RedirectUrl::new(format!("http://{}:{}/oauth/authorized", HOST, PORT).to_string()).expect("redirect url"));

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
    let (code, state) = listen_for_things(listener);

    assert_eq!(&state, csrf_token.secret(), "csrf check");

    let token_result =
        client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(pkce_verifier)
            .add_extra_param("client_id", "commit--cli")  // ??? seems like this isn't sending??
            .request(http_client);
    let tok = token_result.expect("token");

    println!("token_result {:?}", tok);
    tok
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
        }
        _ => unimplemented!()
    }
}
