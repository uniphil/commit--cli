// lkajslfkj not sure how to activate this only for the *crate name*
#![allow(non_snake_case)]

use std::borrow::Cow;
use std::io::{Read, Write};
use std::net::TcpListener;
use structopt::StructOpt;
use httparse::{EMPTY_HEADER, Request, Result as HttpResult, Error::TooManyHeaders};
use keyring::{Entry, Error as KeyringError};
use oauth2::{
    AuthorizationCode,
    AuthUrl,
    ClientId,
    CsrfToken,
    PkceCodeChallenge,
    RedirectUrl,
    Scope,
    TokenUrl,
    url::Url,
};
use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;


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

const HOST: &str = "localhost";
const PORT: u32 = 8000;

fn listen_for_things() -> (String, String) {
    // terrible terrible hacky lil local http server
    let listener = TcpListener::bind(&format!("{}:{}", HOST, PORT)).unwrap();
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

fn oauth() {

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

    println!("Browse to: {}", auth_url);

    println!("waiting....");
    let (code, state) = listen_for_things();

    assert_eq!(&state, csrf_token.secret(), "csrf check");

    let token_result =
        client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(pkce_verifier)
            .add_extra_param("client_id", "commit--cli")  // ??? seems like this isn't sending??
            .request(http_client);
    let tok = token_result.expect("token");

    println!("token_result {:?}", tok);

}

fn main() {
    match Blog::from_args() {
        Blog::Login => {
            oauth();

            let entry = Entry::new("commit--blog", "local");
            match entry.get_password() {
                Ok(token) => println!("yaaaaa: {:?}", token),
                Err(KeyringError::NoEntry) => match entry.set_password("abczzz") {
                    Ok(()) => println!("ya, new set"),
                    Err(err) => eprintln!("naaa setting: {:?}", err),
                },
                Err(err) => eprintln!("naaa: {:?}", err)
            }
        },
        Blog::Logout => {
            let entry = Entry::new("commit--blog", "local");
            match entry.delete_password() {
                Ok(()) => println!("ok password deleted"),
                Err(err) => eprintln!("error deleting pw: {:?}", err),
            }
        }
        _ => unimplemented!()
    }
}
