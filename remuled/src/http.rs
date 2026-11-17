// SPDX-License-Identifier: GPL-2.0-or-later
//! Fetching a file over HTTP(S) (`CHTTPDownloadThread`): redirects followed,
//! at most [`MAX_DOWNLOAD`], within [`TIMEOUT`].

use std::time::Duration;

/// `MAX_HTTP_DOWNLOAD_SIZE`.
pub const MAX_DOWNLOAD: u64 = 256 * 1024 * 1024;
/// The whole request, connect to last byte.
pub const TIMEOUT: Duration = Duration::from_secs(120);

/// The body of `url`, if the server answers 200 with no more than
/// [`MAX_DOWNLOAD`] bytes.
pub async fn fetch(url: &str) -> Result<Vec<u8>, String> {
    let client = reqwest::Client::builder()
        .user_agent("aMule")
        .connect_timeout(Duration::from_secs(30))
        .timeout(TIMEOUT)
        .build()
        .map_err(|e| e.to_string())?;
    let mut resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if resp.status() != reqwest::StatusCode::OK {
        return Err(format!("HTTP {}", resp.status()));
    }
    if resp.content_length().is_some_and(|n| n > MAX_DOWNLOAD) {
        return Err(format!("larger than {} MiB", MAX_DOWNLOAD >> 20));
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if body.len() as u64 + chunk.len() as u64 > MAX_DOWNLOAD {
            return Err(format!("larger than {} MiB", MAX_DOWNLOAD >> 20));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
