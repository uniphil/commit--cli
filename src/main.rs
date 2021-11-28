// lkajslfkj not sure how to activate this only for the *crate name*
#![allow(non_snake_case)]

use structopt::StructOpt;
use keyring::{Entry, Error as KeyringError};

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

fn main() {
    match Blog::from_args() {
        Blog::Login => {
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
