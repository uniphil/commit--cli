#![deny(non_snake_case)]

use httparse::{Error::TooManyHeaders, Request, Result as HttpResult, EMPTY_HEADER};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

pub struct LocalListener<S> {
    listener: TcpListener,
    state: S,
}

pub struct Idle {}

pub struct Heard {
    stream: TcpStream,
}

impl<S> LocalListener<S> {
    pub fn addr(&self) -> Result<String, anyhow::Error> {
        Ok(format!("localhost:{}", self.listener.local_addr()?.port()))
    }
}

impl LocalListener<Idle> {
    pub fn new(port: u16) -> Result<Self, anyhow::Error> {
        let listener = TcpListener::bind(&format!("localhost:{}", port)).or_else(|e| {
            anyhow::bail!(
                "Could not bind to port {} for oauth redirect listener: {:?}",
                port,
                e
            )
        })?;
        Ok(Self {
            listener,
            state: Idle {},
        })
    }
    pub fn listen<F, T>(self, filter: F) -> Result<(LocalListener<Heard>, T), anyhow::Error>
    where
        F: Fn(&Request) -> Option<T>,
    {
        for s in self.listener.incoming() {
            let mut stream = s?;
            let mut buffer = [0; 1024];
            stream.read_exact(&mut buffer)?;
            let mut req = Request::new(&mut [EMPTY_HEADER; 0]);
            match req.parse(&buffer) {
                HttpResult::Err(TooManyHeaders) | HttpResult::Ok(_) => {
                    // we allocated zero headers, so TooManyHeaders is expected
                    if let Some(v) = filter(&req) {
                        return Ok((
                            LocalListener {
                                listener: self.listener,
                                state: Heard { stream },
                            },
                            v,
                        ));
                    }
                    eprintln!("Ignoring request that was filtered out: {:?}", req);
                }
                HttpResult::Err(e) => {
                    eprintln!("Ignoring request that could not be parsed: {:?}", e);
                }
            }
            stream.write_all(b"HTTP/1.1 404 NOT FOUND\r\n\r\n")?;
            stream.flush()?;
        }
        unreachable!()
    }
}

impl LocalListener<Heard> {
    pub fn reply(
        mut self,
        status: &str,
        response: &str,
    ) -> Result<LocalListener<Idle>, anyhow::Error> {
        let resp = format!(
            "HTTP/1.1 {}\r\nContent-Length: {}\r\n\r\n{}",
            status,
            response.len(),
            response
        );
        self.state.stream.write_all(resp.as_bytes())?;
        self.state.stream.flush()?;
        Ok(LocalListener {
            listener: self.listener,
            state: Idle {},
        })
    }
}
