//! JSON-RPC over HTTP, sent with the system's `curl` (feature `rpc`).
//!
//! The tools that talk to a cluster make a handful of requests per run.
//! Running `curl` for them keeps a TLS stack and an HTTP client out of the
//! dependency tree. Nothing in checking a log needs this module.

use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Largest response read. `getClusterNodes` on mainnet is under 2 MB.
const MAX_RESPONSE_BYTES: u64 = 64 << 20;
/// Sends one HTTP POST with a JSON body and returns the status and body.
pub trait Transport {
    /// `Err` is a failure to get any HTTP answer at all.
    fn post(&self, url: &str, body: &str) -> Result<(u16, String), String>;
}

/// The real transport.
pub struct Curl {
    user_agent: &'static str,
}

impl Curl {
    /// A transport that names itself `user_agent` to the server. Give the
    /// tool's name: it says what is asking and nothing about who runs it.
    pub const fn new(user_agent: &'static str) -> Self {
        Self { user_agent }
    }
}

impl Transport for Curl {
    fn post(&self, url: &str, body: &str) -> Result<(u16, String), String> {
        // The URL goes to curl on standard input, in its config syntax: an
        // RPC URL often carries an API key, and arguments show in `ps`.
        // Checked here as well as by the caller, because a quote in it
        // would let it add options of its own.
        host_label(url)?;
        let mut child = Command::new("curl")
            .args(["--silent", "--show-error", "--config", "-"])
            .args(["--proto", "=https,http", "--max-time", "90"])
            .args(["--max-filesize", &MAX_RESPONSE_BYTES.to_string()])
            .args(["--user-agent", self.user_agent])
            .args(["--header", "content-type: application/json"])
            .args(["--data-binary", body])
            .args(["--write-out", "\n%{http_code}"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("could not run curl: {e}"))?;
        let config = format!("url = \"{url}\"\n");
        child
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(config.as_bytes())
            .map_err(|e| format!("could not write to curl: {e}"))?;
        let output = child
            .wait_with_output()
            .map_err(|e| format!("could not wait for curl: {e}"))?;
        if !output.status.success() {
            let why = String::from_utf8_lossy(&output.stderr);
            // curl names the host in some messages and never the path or query.
            return Err(why.trim().trim_start_matches("curl: ").to_string());
        }
        let text = String::from_utf8(output.stdout).map_err(|_| "the answer is not UTF-8")?;
        let (body, status) = text.rsplit_once('\n').ok_or("curl gave no status")?;
        let status = status.parse().map_err(|_| "curl gave no status")?;
        Ok((status, body.to_string()))
    }
}

/// Checks that `url` is an HTTP URL this tool will pass on, and returns the
/// label that names it in a record: the host and port, never the path or
/// query, which are where API keys go.
pub fn host_label(url: &str) -> Result<String, String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or("a URL must start with https:// or http://")?;
    // Nothing that could end the quoted string in curl's config.
    if url
        .bytes()
        .any(|b| !(0x21..=0x7e).contains(&b) || b == b'"' || b == b'\\')
    {
        return Err("a URL must be printable ASCII without quotes or backslashes".into());
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    if host.is_empty() {
        return Err("the URL has no host".into());
    }
    Ok(host.to_ascii_lowercase())
}

/// A JSON-RPC client that is polite to the endpoint: one request at a time,
/// a pause between requests, and a growing wait when told to slow down.
pub struct Rpc<'a> {
    /// What carries the requests.
    pub transport: &'a dyn Transport,
    /// Wait before every request.
    pub pause: Duration,
    /// First wait after a 429 or a 5xx; doubles each time.
    pub backoff: Duration,
    /// Requests made for one call before giving up.
    pub attempts: u32,
}

impl<'a> Rpc<'a> {
    /// The settings for a public endpoint.
    pub fn polite(transport: &'a dyn Transport) -> Self {
        Self {
            transport,
            pause: Duration::from_millis(400),
            backoff: Duration::from_secs(2),
            attempts: 5,
        }
    }

    /// Calls `method` and returns its `result`.
    pub fn call(&self, url: &str, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let mut wait = self.backoff;
        let mut last = String::new();
        for attempt in 0..self.attempts {
            if attempt > 0 {
                std::thread::sleep(wait);
                wait *= 2;
            }
            std::thread::sleep(self.pause);
            let (status, text) = self.transport.post(url, &body.to_string())?;
            if matches!(status, 429 | 502 | 503 | 504) {
                last = format!("{method}: HTTP {status}");
                continue;
            }
            let answer: Value = serde_json::from_str(&text)
                .map_err(|_| format!("{method}: HTTP {status}, and the body is not JSON"))?;
            if let Some(error) = answer.get("error") {
                return Err(format!("{method}: {error}"));
            }
            return answer
                .get("result")
                .cloned()
                .ok_or_else(|| format!("{method}: HTTP {status}, and no result"));
        }
        Err(format!("{last}, {} times", self.attempts))
    }
}

/// A transport for tests of code that calls a node.
pub mod testing {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    /// Answers requests from a script and records what was asked.
    #[derive(Default)]
    pub struct Scripted {
        /// The status and body of each answer still to give, in order.
        pub answers: RefCell<VecDeque<(u16, String)>>,
        /// The URL and JSON body of every request so far.
        pub asked: RefCell<Vec<(String, Value)>>,
    }

    impl Scripted {
        /// A transport that gives `answers` in order and then refuses.
        pub fn new(answers: &[(u16, &str)]) -> Self {
            Self {
                answers: RefCell::new(answers.iter().map(|(s, b)| (*s, b.to_string())).collect()),
                asked: RefCell::default(),
            }
        }

        /// A client on this transport that never waits.
        pub fn rpc(&self) -> Rpc<'_> {
            Rpc {
                transport: self,
                pause: Duration::ZERO,
                backoff: Duration::ZERO,
                attempts: 3,
            }
        }
    }

    impl Transport for Scripted {
        fn post(&self, url: &str, body: &str) -> Result<(u16, String), String> {
            self.asked
                .borrow_mut()
                .push((url.to_string(), serde_json::from_str(body).unwrap()));
            self.answers
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| "connection refused".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Scripted;
    use super::*;

    #[test]
    fn a_label_is_the_host_and_never_the_key() {
        assert_eq!(
            host_label("https://api.devnet.solana.com"),
            Ok("api.devnet.solana.com".into())
        );
        assert_eq!(
            host_label("https://RPC.example.com/v1/SECRET?api-key=SECRET#x"),
            Ok("rpc.example.com".into())
        );
        assert_eq!(
            host_label("http://user:SECRET@192.0.2.7:8899/"),
            Ok("192.0.2.7:8899".into())
        );
        assert_eq!(
            host_label("http://[2001:db8::1]:8899"),
            Ok("[2001:db8::1]:8899".into())
        );
        for bad in [
            "ftp://example.com",
            "example.com",
            "https://",
            "https:///path",
            "https://exa mple.com",
            "https://example.com/\"\nurl = \"https://elsewhere.example",
            "https://example.com/a\\b",
        ] {
            assert!(host_label(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_call_sends_json_rpc_and_returns_the_result() {
        let transport = Scripted::new(&[(200, r#"{"jsonrpc":"2.0","id":1,"result":{"a":7}}"#)]);
        let result = transport.rpc().call("http://node", "getThing", json!([5]));
        assert_eq!(result, Ok(json!({"a": 7})));
        let asked = transport.asked.borrow();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].0, "http://node");
        assert_eq!(
            asked[0].1,
            json!({"jsonrpc": "2.0", "id": 1, "method": "getThing", "params": [5]})
        );
    }

    #[test]
    fn a_request_to_slow_down_is_obeyed_and_then_given_up_on() {
        let ok = r#"{"jsonrpc":"2.0","id":1,"result":1}"#;
        let transport = Scripted::new(&[(429, "slow down"), (503, ""), (200, ok)]);
        assert_eq!(transport.rpc().call("u", "m", json!([])), Ok(json!(1)));
        assert_eq!(transport.asked.borrow().len(), 3);

        let transport = Scripted::new(&[(429, ""), (429, ""), (429, ""), (200, ok)]);
        assert_eq!(
            transport.rpc().call("u", "m", json!([])),
            Err("m: HTTP 429, 3 times".into())
        );
        assert_eq!(transport.asked.borrow().len(), 3);
    }

    #[test]
    fn errors_are_passed_on_and_not_retried() {
        let error =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#;
        let transport = Scripted::new(&[(200, error), (200, error)]);
        let result = transport.rpc().call("u", "m", json!([]));
        assert!(result.unwrap_err().contains("Method not found"));
        assert_eq!(transport.asked.borrow().len(), 1);

        let transport = Scripted::new(&[(404, "<html>not here</html>")]);
        assert_eq!(
            transport.rpc().call("u", "m", json!([])),
            Err("m: HTTP 404, and the body is not JSON".into())
        );
        let transport = Scripted::new(&[]);
        assert_eq!(
            transport.rpc().call("u", "m", json!([])),
            Err("connection refused".into())
        );
    }
}
