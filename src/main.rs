// lkajslfkj not sure how to activate this only for the *crate name*
#![allow(non_snake_case)]

use std::io;
use structopt::StructOpt;
use keyring::{Entry, Error as KeyringError};
use oauth2::{
    AuthorizationCode,
    AuthUrl,
    ClientId,
    CsrfToken,
    PkceCodeChallenge,
    RedirectUrl,
    Scope,
    TokenUrl
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

fn oauth() {

    let client =
        BasicClient::new(
            ClientId::new("commit--cli".to_string()),
            None,
            AuthUrl::new("http://localhost:5000/oauth/auth".to_string()).expect("auth url"),
            Some(TokenUrl::new("http://localhost:5000/oauth/token".to_string()).expect("token url"))
        )
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_uri(RedirectUrl::new("http://localhost:8000".to_string()).expect("redirect url"));

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("blog".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    println!("Browse to: {}", auth_url);

    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("error: unable to read user input");

    let token_result =
        client
            .exchange_code(AuthorizationCode::new(input))
            .set_pkce_verifier(pkce_verifier)
            .request(http_client).expect("token");

    println!("token_result {:?}", token_result);

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
