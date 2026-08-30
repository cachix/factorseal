//! Minimal TPM 2.0 command codec used by operating-system TPM transports.

use crate::Error;
use zeroize::Zeroizing;

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS: u16 = 0x8002;
const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const TPM_CC_CREATE: u32 = 0x0000_0153;
const TPM_CC_LOAD: u32 = 0x0000_0157;
const TPM_CC_UNSEAL: u32 = 0x0000_015e;
const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const TPM_RH_OWNER: u32 = 0x4000_0001;
const TPM_RS_PW: u32 = 0x4000_0009;

const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_KEYEDHASH: u16 = 0x0008;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_SYMCIPHER: u16 = 0x0025;
const TPM_ALG_CFB: u16 = 0x0043;

const PRIMARY_ATTRIBUTES: u32 = 0x0003_0072;
const SEALED_ATTRIBUTES: u32 = 0x0000_04d2;
const RESPONSE_HEADER_BYTES: usize = 10;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

pub(super) trait Transport {
    fn execute(&mut self, command: &[u8]) -> Result<Vec<u8>, Error>;

    fn owner_auth(&mut self) -> Result<Zeroizing<Vec<u8>>, Error> {
        Ok(Zeroizing::new(Vec::new()))
    }
}

pub(super) struct SealedObject {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

pub(super) fn probe(transport: &mut impl Transport) -> Result<(), Error> {
    let primary = create_primary(transport)?;
    flush(transport, primary)
}

pub(super) fn seal(
    transport: &mut impl Transport,
    sensitive: &[u8],
) -> Result<SealedObject, Error> {
    let primary = create_primary(transport)?;
    let result = create_sealed(transport, primary, sensitive);
    let flushed = flush(transport, primary);
    match (result, flushed) {
        (Ok(object), Ok(())) => Ok(object),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

pub(super) fn unseal(
    transport: &mut impl Transport,
    public: &[u8],
    private: &[u8],
) -> Result<Vec<u8>, Error> {
    let primary = create_primary(transport)?;
    let child = match load(transport, primary, public, private) {
        Ok(child) => child,
        Err(error) => {
            let _ = flush(transport, primary);
            return Err(error);
        }
    };
    let result = unseal_loaded(transport, child);
    let child_flush = flush(transport, child);
    let primary_flush = flush(transport, primary);
    match (result, child_flush, primary_flush) {
        (Ok(secret), Ok(()), Ok(())) => Ok(secret),
        (Err(error), _, _) | (Ok(_), Err(error), _) | (Ok(_), Ok(()), Err(error)) => Err(error),
    }
}

fn create_primary(transport: &mut impl Transport) -> Result<u32, Error> {
    let owner_auth = transport.owner_auth()?;
    let mut body = Writer::default();
    body.u32(TPM_RH_OWNER);
    body.password_session(&owner_auth);
    body.sized(|sensitive| {
        sensitive.sized(|_| {});
        sensitive.sized(|_| {});
    });
    body.sized(|public| {
        public.u16(TPM_ALG_SYMCIPHER);
        public.u16(TPM_ALG_SHA256);
        public.u32(PRIMARY_ATTRIBUTES);
        public.sized(|_| {});
        public.u16(TPM_ALG_AES);
        public.u16(256);
        public.u16(TPM_ALG_CFB);
        public.sized(|_| {});
    });
    body.sized(|_| {});
    body.u32(0);

    let response = submit(transport, TPM_ST_SESSIONS, TPM_CC_CREATE_PRIMARY, body)?;
    response_handle(&response)
}

fn create_sealed(
    transport: &mut impl Transport,
    parent: u32,
    sensitive_data: &[u8],
) -> Result<SealedObject, Error> {
    let mut body = Writer::default();
    body.u32(parent);
    body.password_session(&[]);
    body.sized(|sensitive| {
        sensitive.sized(|_| {});
        sensitive.sized(|data| data.bytes(sensitive_data));
    });
    body.sized(|public| {
        public.u16(TPM_ALG_KEYEDHASH);
        public.u16(TPM_ALG_SHA256);
        public.u32(SEALED_ATTRIBUTES);
        public.sized(|_| {});
        public.u16(TPM_ALG_NULL);
        public.sized(|_| {});
    });
    body.sized(|_| {});
    body.u32(0);

    let response = submit(transport, TPM_ST_SESSIONS, TPM_CC_CREATE, body)?;
    let params = response_parameters(&response, 0)?;
    let mut reader = Reader::new(params);
    let private = reader.sized()?.to_vec();
    let public = reader.sized()?.to_vec();
    Ok(SealedObject { public, private })
}

fn load(
    transport: &mut impl Transport,
    parent: u32,
    public: &[u8],
    private: &[u8],
) -> Result<u32, Error> {
    let mut body = Writer::default();
    body.u32(parent);
    body.password_session(&[]);
    body.sized(|blob| blob.bytes(private));
    body.sized(|blob| blob.bytes(public));
    let response = submit(transport, TPM_ST_SESSIONS, TPM_CC_LOAD, body)?;
    response_handle(&response)
}

fn unseal_loaded(transport: &mut impl Transport, child: u32) -> Result<Vec<u8>, Error> {
    let mut body = Writer::default();
    body.u32(child);
    body.password_session(&[]);
    let response = submit(transport, TPM_ST_SESSIONS, TPM_CC_UNSEAL, body)?;
    let params = response_parameters(&response, 0)?;
    Reader::new(params).sized().map(ToOwned::to_owned)
}

fn flush(transport: &mut impl Transport, handle: u32) -> Result<(), Error> {
    let mut body = Writer::default();
    body.u32(handle);
    submit(transport, TPM_ST_NO_SESSIONS, TPM_CC_FLUSH_CONTEXT, body).map(drop)
}

fn submit(
    transport: &mut impl Transport,
    tag: u16,
    command_code: u32,
    body: Writer,
) -> Result<Vec<u8>, Error> {
    let body = body.finish();
    let length = u32::try_from(RESPONSE_HEADER_BYTES + body.len())
        .map_err(|_| Error::Hardware("TPM command is too large".to_owned()))?;
    let mut command = Vec::with_capacity(length as usize);
    command.extend_from_slice(&tag.to_be_bytes());
    command.extend_from_slice(&length.to_be_bytes());
    command.extend_from_slice(&command_code.to_be_bytes());
    command.extend_from_slice(&body);
    let response = transport.execute(&command)?;
    validate_response(&response)?;
    Ok(response)
}

fn validate_response(response: &[u8]) -> Result<(), Error> {
    if response.len() < RESPONSE_HEADER_BYTES || response.len() > MAX_RESPONSE_BYTES {
        return Err(Error::Hardware("invalid TPM response length".to_owned()));
    }
    let declared = read_u32(response, 2)? as usize;
    if declared != response.len() {
        return Err(Error::Hardware(
            "TPM response length does not match its header".to_owned(),
        ));
    }
    let response_code = read_u32(response, 6)?;
    if response_code != 0 {
        return Err(Error::Hardware(format!(
            "TPM command failed with response code 0x{response_code:08x}"
        )));
    }
    Ok(())
}

fn response_handle(response: &[u8]) -> Result<u32, Error> {
    read_u32(response, RESPONSE_HEADER_BYTES)
}

fn response_parameters(response: &[u8], handle_count: usize) -> Result<&[u8], Error> {
    let mut offset = RESPONSE_HEADER_BYTES
        .checked_add(handle_count * 4)
        .ok_or_else(|| Error::Hardware("TPM response offset overflow".to_owned()))?;
    let tag = read_u16(response, 0)?;
    if tag == TPM_ST_SESSIONS {
        let size = read_u32(response, offset)? as usize;
        offset += 4;
        return response
            .get(offset..offset.saturating_add(size))
            .ok_or_else(|| Error::Hardware("truncated TPM response parameters".to_owned()));
    }
    if tag != TPM_ST_NO_SESSIONS {
        return Err(Error::Hardware(format!(
            "unknown TPM response tag 0x{tag:04x}"
        )));
    }
    response
        .get(offset..)
        .ok_or_else(|| Error::Hardware("truncated TPM response".to_owned()))
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, Error> {
    let bytes = input
        .get(offset..offset.saturating_add(2))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::Hardware("truncated TPM response".to_owned()))?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, Error> {
    let bytes = input
        .get(offset..offset.saturating_add(4))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::Hardware("truncated TPM response".to_owned()))?;
    Ok(u32::from_be_bytes(bytes))
}

#[derive(Default)]
struct Writer(Vec<u8>);

impl Writer {
    fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }

    fn sized(&mut self, write: impl FnOnce(&mut Self)) {
        let length_offset = self.0.len();
        self.u16(0);
        let value_offset = self.0.len();
        write(self);
        let length = self.0.len() - value_offset;
        let length = u16::try_from(length).expect("TPM2B value exceeds u16");
        self.0[length_offset..value_offset].copy_from_slice(&length.to_be_bytes());
    }

    fn password_session(&mut self, auth: &[u8]) {
        let auth_len = u16::try_from(auth.len()).expect("TPM authorization exceeds u16");
        self.u32(9 + u32::from(auth_len));
        self.u32(TPM_RS_PW);
        self.u16(0);
        self.0.push(0);
        self.u16(auth_len);
        self.bytes(auth);
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn sized(&mut self) -> Result<&'a [u8], Error> {
        let length = read_u16(self.input, self.offset)? as usize;
        self.offset += 2;
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| Error::Hardware("TPM2B length overflow".to_owned()))?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or_else(|| Error::Hardware("truncated TPM2B value".to_owned()))?;
        self.offset = end;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    struct Device(std::fs::File);

    #[cfg(target_os = "linux")]
    impl Transport for Device {
        fn execute(&mut self, command: &[u8]) -> Result<Vec<u8>, Error> {
            use std::io::{Read as _, Write as _};

            self.0
                .write_all(command)
                .map_err(|error| Error::Hardware(error.to_string()))?;
            let mut response = vec![0; MAX_RESPONSE_BYTES];
            let length = self
                .0
                .read(&mut response)
                .map_err(|error| Error::Hardware(error.to_string()))?;
            response.truncate(length);
            Ok(response)
        }
    }

    #[test]
    fn sized_values_roundtrip() {
        let mut writer = Writer::default();
        writer.sized(|value| value.bytes(b"secret"));
        let encoded = writer.finish();
        assert_eq!(Reader::new(&encoded).sized().expect("parse"), b"secret");
    }

    #[test]
    fn responses_reject_length_mismatch() {
        let response = [0x80, 0x01, 0, 0, 0, 11, 0, 0, 0, 0];
        assert!(validate_response(&response).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn raw_tpm_roundtrip_when_requested() {
        if std::env::var_os("HARDWARESEAL_RAW_TPM_TEST").is_none() {
            return;
        }

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tpmrm0")
            .expect("open TPM resource manager");
        let mut device = Device(file);
        let expected = b"raw-hardwareseal-roundtrip";
        let object = seal(&mut device, expected).expect("seal");
        let actual = unseal(&mut device, &object.public, &object.private).expect("unseal");
        assert_eq!(actual, expected);
    }
}
