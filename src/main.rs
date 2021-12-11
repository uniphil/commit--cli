// lkajslfkj not sure how to activate this only for the *crate name*
#![allow(non_snake_case)]

use anyhow::Context;
use git2::{Commit, Repository};
use keyring::Entry;
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use structopt::StructOpt;

mod auth;
mod local_listener;

#[derive(Debug, StructOpt)]
#[structopt(name = "commit--blog")]
enum Blog {
    /// Authorize commit--cli to manage commit--blog posts for your account
    Login {
        /// Delete the cli's access token, effectively revoking cli access
        #[structopt(short, long)]
        delete: bool,
    },
    /// Publish a commit as a commit--blog post!
    Post {
        /// Unpost/delete a commit blogpost that has already been posted.
        #[structopt(short, long)]
        delete: bool,
        /// A reference to identify the commit, like its hash or a tag.
        /// Defaults to the latest commit on the current branch.
        #[structopt(name = "ref")]
        git_ref: Option<String>,
    },
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

fn post(
    commit: Commit,
    origin: GitOrigin,
    token: auth::StoredToken,
    delete: bool,
    blog_host: &str,
) -> Result<(), anyhow::Error> {
    let route = format!("{}/api/blog/{}", blog_host, commit.id());
    let action = if delete {
        ureq::delete(&route)
    } else {
        ureq::put(&route)
    };
    let resp = action
        .set("User-Agent", "commit--cli hacky test version")
        .set("Authorization", &format!("Bearer {}", token.to_bearer()))
        .set("Content-Type", "application/json")
        .send_string(&serde_json::to_string(&origin)?)?;

    if resp.status() >= 300 {
        anyhow::bail!("{}: {}", resp.status(), resp.into_string()?)
    }
    if delete {
        println!("post deleted.");
    } else {
        let data: HashMap<String, String> = serde_json::from_reader(resp.into_reader())?;
        println!("{:#?}", data);
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
    let commitblog_host =
        env::var("COMMITBLOG_HOST").unwrap_or_else(|_| "https://commit--blog.com".to_string());
    let entry = Entry::new(&commitblog_host, "commit--cli");
    match Blog::from_args() {
        Blog::Login { delete: false } => {
            if let Some(token) = auth::get_token(&entry)? {
                // TODO: send an auth validation request to the commitblog host
                println!("Already logged in: found {}", token.info());
            } else {
                let raw_auth = auth::oauth(&commitblog_host)?;
                let token = auth::StoredToken::from_token_response(raw_auth);
                let s = serde_json::to_string(&token)?;
                entry.set_password(&s)?;
                println!("Access token saved.")
            }
        }
        Blog::Login { delete: true } => {
            if let Some(token) = auth::get_token(&entry)? {
                let revoked = !auth::revoke(token, &commitblog_host)?;
                entry.delete_password()?;
                println!(
                    "Access token {}deleted.",
                    if revoked { "revoked and " } else { "" }
                );
            } else {
                println!("No access token found.");
            }
        }
        Blog::Post { git_ref, delete } => {
            let token = auth::get_token(&entry)?.context("Log in to post")?;
            let repo = Repository::discover(env::current_dir()?)?;
            let commit = get_commit(&repo, git_ref)?;
            let origin = get_likely_origin(&repo)?;
            post(commit, origin, token, delete, &commitblog_host)?
        }
    }
    Ok(())
}
