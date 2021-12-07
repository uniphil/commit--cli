// lkajslfkj not sure how to activate this only for the *crate name*
#![allow(non_snake_case)]

use anyhow::Context;
use git2::{Commit, Repository};
use keyring::Entry;
use reqwest::{header, StatusCode};
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use structopt::StructOpt;

mod auth;
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

fn post(commit: Commit, origin: GitOrigin, token: auth::StoredToken) -> Result<(), reqwest::Error> {
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

fn unpost(
    commit: Commit,
    origin: GitOrigin,
    token: auth::StoredToken,
) -> Result<(), reqwest::Error> {
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
            if let Some(token) = auth::get_token(&entry)? {
                println!("Already logged in: found {}", token.info());
            } else {
                let raw_auth = auth::oauth()?;
                let token = auth::StoredToken::from_token_response(raw_auth);
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
            let token = auth::get_token(&entry)?.context("Log in to post")?;
            let repo = Repository::discover(env::current_dir()?)?;
            let commit = get_commit(&repo, git_ref)?;
            let origin = get_likely_origin(&repo)?;
            post(commit, origin, token)?
        }
        Blog::Unpost { git_ref } => {
            let token = auth::get_token(&entry)?.context("Log in to unpost")?;
            let repo = Repository::discover(env::current_dir()?)?;
            let commit = get_commit(&repo, git_ref)?;
            let origin = get_likely_origin(&repo)?;
            unpost(commit, origin, token)?
        }
    }
    Ok(())
}
