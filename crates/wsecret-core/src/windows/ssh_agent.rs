//! Windows OpenSSH agent client (Ed25519 only).
//!
//! The existing Microsoft `ssh-agent` service performs all signing. This
//! module only transports add/remove/list/sign requests over its named pipe.
//! Private keys are never written to disk; add-key payloads live in
//! [`SecretBytes`] and are wiped on every return path.

use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING, ReadFile, WriteFile,
};

use crate::error::{AgentError, Error};
use crate::session::SecretBytes;

/// Default Microsoft Win32-OpenSSH agent endpoint.
pub const DEFAULT_SSH_AGENT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";
const MAX_FRAME: usize = 256 * 1024;
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH2_AGENTC_ADD_IDENTITY: u8 = 17;
const SSH2_AGENTC_REMOVE_IDENTITY: u8 = 18;

fn unavailable() -> Error {
    Error::Agent(AgentError::Unavailable)
}

fn mismatch() -> Error {
    Error::Agent(AgentError::ProtocolMismatch)
}

/// One Ed25519 identity returned by `SSH2_AGENT_IDENTITIES_ANSWER`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshAgentIdentity {
    pub public: [u8; 32],
    pub comment: Vec<u8>,
}

/// Synchronous client for one Windows OpenSSH agent endpoint.
pub struct SshAgentClient {
    pipe_name: String,
}

impl SshAgentClient {
    pub fn new() -> Self {
        Self::with_pipe(DEFAULT_SSH_AGENT_PIPE)
    }

    pub fn with_pipe(pipe_name: &str) -> Self {
        Self {
            pipe_name: pipe_name.to_owned(),
        }
    }

    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    /// Adds one 64-byte Ed25519 secret key (private scalar || public key).
    /// The caller's secret and the secure request are wiped on every return.
    pub fn add_ed25519(&self, secret: &mut [u8], comment: &[u8]) -> Result<(), Error> {
        if secret.len() != 64 {
            libhydrogen_sys::memzero(secret);
            return Err(mismatch());
        }
        let public: [u8; 32] = secret[32..64].try_into().expect("length checked");
        let mut payload = SecretBytes::new(1 + 4 + 11 + 4 + 32 + 4 + 64 + 4 + comment.len())?;
        let result = {
            let buf = payload.as_mut_slice();
            buf[0] = SSH2_AGENTC_ADD_IDENTITY;
            let mut pos = 1;
            let encoded = (|| {
                put_string(buf, &mut pos, b"ssh-ed25519")?;
                put_string(buf, &mut pos, &public)?;
                put_string(buf, &mut pos, secret)?;
                put_string(buf, &mut pos, comment)
            })();
            match encoded {
                Ok(()) => self.request(buf),
                Err(error) => Err(error),
            }
        };
        libhydrogen_sys::memzero(secret);
        payload.clear();
        expect_success(&result?)
    }

    /// Removes one Ed25519 identity by public key. No private material is
    /// needed for this request.
    pub fn remove_ed25519(&self, public: &[u8; 32]) -> Result<(), Error> {
        let blob = key_blob(public);
        let mut payload = vec![0u8; 1 + 4 + blob.len()];
        payload[0] = SSH2_AGENTC_REMOVE_IDENTITY;
        put_string(&mut payload, &mut 1, &blob)?;
        expect_success(&self.request(&mut payload)?)
    }

    /// Lists Ed25519 identities currently held by the agent.
    pub fn identities(&self) -> Result<Vec<SshAgentIdentity>, Error> {
        let response = self.request(&mut [SSH2_AGENTC_REQUEST_IDENTITIES])?;
        parse_identities(&response)
    }

    /// Signs `data` with the named Ed25519 key and returns the 64-byte
    /// signature. The Microsoft agent performs the private-key operation.
    pub fn sign_ed25519(&self, public: &[u8; 32], data: &[u8]) -> Result<[u8; 64], Error> {
        let blob = key_blob(public);
        let mut payload = vec![0u8; 1 + 4 + blob.len() + 4 + data.len() + 4];
        payload[0] = SSH2_AGENTC_SIGN_REQUEST;
        let mut pos = 1;
        put_string(&mut payload, &mut pos, &blob)?;
        put_string(&mut payload, &mut pos, data)?;
        payload.extend_from_slice(&0u32.to_be_bytes());
        let response = self.request(&mut payload)?;
        parse_signature(&response)
    }

    /// Writes one length-prefixed request and reads one bounded response.
    /// Request and response bodies are streamed separately so a private add
    /// payload is never copied into a second ordinary frame buffer.
    fn request(&self, payload: &mut [u8]) -> Result<Vec<u8>, Error> {
        if payload.is_empty() || payload.len() > MAX_FRAME {
            return Err(mismatch());
        }
        let wide: Vec<u16> = self
            .pipe_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `wide` is NUL-terminated; no security attributes are needed
        // to open the existing user agent endpoint.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(unavailable());
        }
        let handle = OwnedHandle(raw);
        let len = (payload.len() as u32).to_be_bytes();
        write_all(handle.0, &len)?;
        write_all(handle.0, payload)?;

        let mut header = [0u8; 4];
        read_exact(handle.0, &mut header)?;
        let response_len = u32::from_be_bytes(header) as usize;
        if response_len == 0 || response_len > MAX_FRAME {
            return Err(mismatch());
        }
        let mut response = vec![0u8; response_len];
        read_exact(handle.0, &mut response)?;
        Ok(response)
    }
}

impl Default for SshAgentClient {
    fn default() -> Self {
        Self::new()
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: owned live pipe handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn write_all(handle: HANDLE, mut bytes: &[u8]) -> Result<(), Error> {
    while !bytes.is_empty() {
        let mut written = 0u32;
        // SAFETY: `bytes` is readable for the requested length and `written`
        // points to a valid u32.
        let ok = unsafe {
            WriteFile(
                handle,
                bytes.as_ptr().cast(),
                bytes.len() as u32,
                &mut written,
                ptr::null_mut(),
            )
        };
        if ok == 0 || written == 0 {
            return Err(unavailable());
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

fn read_exact(handle: HANDLE, mut out: &mut [u8]) -> Result<(), Error> {
    while !out.is_empty() {
        let mut read = 0u32;
        // SAFETY: `out` is writable for the requested length and `read`
        // points to a valid u32.
        let ok = unsafe {
            ReadFile(
                handle,
                out.as_mut_ptr().cast(),
                out.len() as u32,
                &mut read,
                ptr::null_mut(),
            )
        };
        if ok == 0 || read == 0 {
            return Err(unavailable());
        }
        out = &mut out[read as usize..];
    }
    Ok(())
}

fn put_string(out: &mut [u8], pos: &mut usize, value: &[u8]) -> Result<(), Error> {
    let len = u32::try_from(value.len()).map_err(|_| mismatch())?;
    let end = pos.checked_add(4 + value.len()).ok_or_else(mismatch)?;
    if end > out.len() {
        return Err(mismatch());
    }
    out[*pos..*pos + 4].copy_from_slice(&len.to_be_bytes());
    *pos += 4;
    out[*pos..end].copy_from_slice(value);
    *pos = end;
    Ok(())
}

fn take_string<'a>(input: &'a [u8], pos: &mut usize) -> Result<&'a [u8], Error> {
    if *pos + 4 > input.len() {
        return Err(mismatch());
    }
    let len = u32::from_be_bytes(input[*pos..*pos + 4].try_into().expect("four bytes")) as usize;
    *pos += 4;
    let end = pos.checked_add(len).ok_or_else(mismatch)?;
    if end > input.len() {
        return Err(mismatch());
    }
    let value = &input[*pos..end];
    *pos = end;
    Ok(value)
}

fn take_u32(input: &[u8], pos: &mut usize) -> Result<u32, Error> {
    if *pos + 4 > input.len() {
        return Err(mismatch());
    }
    let value = u32::from_be_bytes(input[*pos..*pos + 4].try_into().expect("four bytes"));
    *pos += 4;
    Ok(value)
}

fn key_blob(public: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(4 + 11 + 4 + 32);
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    blob.extend_from_slice(public);
    blob
}

fn expect_success(response: &[u8]) -> Result<(), Error> {
    if response == [SSH_AGENT_SUCCESS] {
        Ok(())
    } else if response == [SSH_AGENT_FAILURE] {
        Err(mismatch())
    } else {
        Err(mismatch())
    }
}

fn parse_identities(response: &[u8]) -> Result<Vec<SshAgentIdentity>, Error> {
    if response.first().copied() != Some(SSH2_AGENT_IDENTITIES_ANSWER) {
        return Err(mismatch());
    }
    let mut pos = 1;
    let count = take_u32(response, &mut pos)? as usize;
    let mut out = Vec::new();
    for _ in 0..count {
        let blob = take_string(response, &mut pos)?;
        let comment = take_string(response, &mut pos)?.to_vec();
        let mut blob_pos = 0;
        let kind = take_string(blob, &mut blob_pos)?;
        if kind == b"ssh-ed25519" {
            let public = take_string(blob, &mut blob_pos)?;
            if public.len() != 32 || blob_pos != blob.len() {
                return Err(mismatch());
            }
            out.push(SshAgentIdentity {
                public: public.try_into().expect("32 bytes checked"),
                comment,
            });
        }
    }
    if pos != response.len() {
        return Err(mismatch());
    }
    Ok(out)
}

fn parse_signature(response: &[u8]) -> Result<[u8; 64], Error> {
    if response.first().copied() != Some(SSH2_AGENT_SIGN_RESPONSE) {
        return Err(mismatch());
    }
    let mut pos = 1;
    let blob = take_string(response, &mut pos)?;
    if pos != response.len() {
        return Err(mismatch());
    }
    let mut blob_pos = 0;
    let kind = take_string(blob, &mut blob_pos)?;
    if kind != b"ssh-ed25519" {
        return Err(mismatch());
    }
    let signature = take_string(blob, &mut blob_pos)?;
    if signature.len() != 64 || blob_pos != blob.len() {
        return Err(mismatch());
    }
    Ok(signature.try_into().expect("64 bytes checked"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn append_string(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }

    #[test]
    fn key_blob_has_exact_ssh_ed25519_layout() {
        let public = [7u8; 32];
        let blob = key_blob(&public);
        assert_eq!(&blob[..4], &11u32.to_be_bytes());
        assert_eq!(&blob[4..15], b"ssh-ed25519");
        assert_eq!(&blob[15..19], &32u32.to_be_bytes());
        assert_eq!(&blob[19..], &public);
    }

    #[test]
    fn identities_parser_skips_other_key_types_and_rejects_trailing_bytes() {
        let mut response = vec![SSH2_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 2];
        let mut rsa_blob = Vec::new();
        append_string(&mut rsa_blob, b"ssh-rsa");
        append_string(&mut rsa_blob, b"ignored-public");
        append_string(&mut response, &rsa_blob);
        append_string(&mut response, b"ignored");
        let blob = key_blob(&[9u8; 32]);
        append_string(&mut response, &blob);
        append_string(&mut response, b"comment");
        let parsed = parse_identities(&response).expect("parse identities");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].public, [9u8; 32]);
        assert_eq!(parsed[0].comment, b"comment");

        let mut bad = response;
        bad.push(0);
        assert!(parse_identities(&bad).is_err());
    }

    #[test]
    fn signature_parser_requires_exact_ed25519_blob() {
        let signature = [0x5au8; 64];
        let mut response = vec![SSH2_AGENT_SIGN_RESPONSE];
        let mut blob = Vec::new();
        append_string(&mut blob, b"ssh-ed25519");
        append_string(&mut blob, &signature);
        append_string(&mut response, &blob);
        assert_eq!(parse_signature(&response).expect("signature"), signature);

        let mut bad = response;
        bad.push(0);
        assert!(parse_signature(&bad).is_err());
    }
}
