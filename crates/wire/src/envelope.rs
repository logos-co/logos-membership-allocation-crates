use sha2::{Digest, Sha256};

use crate::proto::{as_bytes, as_string, as_u64, put_len_field, put_varint_field, walk_fields};

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct SponsorRequest {
    pub request_id: String,
    pub authentication_type: Vec<u8>,
    pub authentication_payload: Vec<u8>,
    pub action_kind: String,
    pub action: Vec<u8>,
    pub scope: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Granted,
    Refused,
    NotSubmitted,
    Unconfirmed,
}

impl Status {
    fn to_wire(self) -> u64 {
        match self {
            Status::Granted => 1,
            Status::Refused => 2,
            Status::NotSubmitted => 3,
            Status::Unconfirmed => 4,
        }
    }

    fn from_wire(v: u64) -> Option<Status> {
        Some(match v {
            1 => Status::Granted,
            2 => Status::Refused,
            3 => Status::NotSubmitted,
            4 => Status::Unconfirmed,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SponsorResponse {
    pub request_id: String,
    pub status: Status,
    pub message: Option<String>,
    pub result: Option<Vec<u8>>,
    pub code: Option<String>,
}

impl SponsorRequest {
    pub fn action_digest(&self) -> [u8; 32] {
        let scope = self.scope.as_deref().unwrap_or("");
        let mut h = Sha256::new();
        for part in [
            scope.as_bytes(),
            self.action_kind.as_bytes(),
            self.action.as_slice(),
        ] {
            h.update((part.len() as u64).to_le_bytes());
            h.update(part);
        }
        h.finalize().into()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_len_field(&mut out, 1, self.request_id.as_bytes());
        if !self.authentication_type.is_empty() {
            put_len_field(&mut out, 2, &self.authentication_type);
        }
        if !self.authentication_payload.is_empty() {
            put_len_field(&mut out, 3, &self.authentication_payload);
        }
        put_len_field(&mut out, 4, self.action_kind.as_bytes());
        put_len_field(&mut out, 5, &self.action);
        if let Some(scope) = &self.scope {
            put_len_field(&mut out, 6, scope.as_bytes());
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<SponsorRequest, String> {
        let mut m = SponsorRequest::default();
        let mut have_id = false;
        let mut have_kind = false;
        walk_fields(buf, |field, v| match field {
            1 => {
                m.request_id = as_string(v);
                have_id = true;
            }
            2 => m.authentication_type = as_bytes(v),
            3 => m.authentication_payload = as_bytes(v),
            4 => {
                m.action_kind = as_string(v);
                have_kind = true;
            }
            5 => m.action = as_bytes(v),
            6 => m.scope = Some(as_string(v)),
            _ => {}
        })?;
        if !have_id {
            return Err("missing request_id".into());
        }
        if !have_kind {
            return Err("missing action_kind".into());
        }
        Ok(m)
    }
}

impl SponsorResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_len_field(&mut out, 1, self.request_id.as_bytes());
        put_varint_field(&mut out, 2, self.status.to_wire());
        if let Some(m) = &self.message {
            put_len_field(&mut out, 3, m.as_bytes());
        }
        if let Some(r) = &self.result {
            put_len_field(&mut out, 4, r);
        }
        if let Some(c) = &self.code {
            put_len_field(&mut out, 5, c.as_bytes());
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<SponsorResponse, String> {
        let mut request_id = None;
        let mut status = None;
        let (mut message, mut result, mut code) = (None, None, None);
        walk_fields(buf, |field, v| match field {
            1 => request_id = Some(as_string(v)),
            2 => status = Some(as_u64(v)),
            3 => message = Some(as_string(v)),
            4 => result = Some(as_bytes(v)),
            5 => code = Some(as_string(v)),
            _ => {}
        })?;
        let status = status.ok_or("missing status")?;
        Ok(SponsorResponse {
            request_id: request_id.ok_or("missing request_id")?,
            status: Status::from_wire(status).ok_or_else(|| format!("unknown status {status}"))?,
            message,
            result,
            code,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_round_trips_and_its_bytes_are_fixed() {
        let req = SponsorRequest {
            request_id: "x".into(),
            authentication_type: b"t".to_vec(),
            authentication_payload: vec![],
            action_kind: "k".into(),
            action: vec![0xff],
            scope: Some("s".into()),
        };
        let bytes = req.encode();
        assert_eq!(
            bytes,
            vec![
                0x0A, 0x01, b'x', 0x12, 0x01, b't', 0x22, 0x01, b'k', 0x2A, 0x01, 0xff, 0x32, 0x01,
                b's'
            ]
        );
        assert_eq!(SponsorRequest::decode(&bytes).unwrap(), req);
        let bare = SponsorRequest {
            authentication_type: vec![],
            scope: None,
            ..req
        };
        assert_eq!(SponsorRequest::decode(&bare.encode()).unwrap(), bare);
        assert_eq!(
            SponsorRequest::decode(&[0x0A, 0x01, b'x']).unwrap_err(),
            "missing action_kind"
        );
        assert_eq!(
            SponsorRequest::decode(&[0x22, 0x01, b'k']).unwrap_err(),
            "missing request_id"
        );
    }

    #[test]
    fn the_action_digest_covers_scope_kind_and_action_but_not_the_auth_fields() {
        let base = SponsorRequest {
            request_id: "a".into(),
            action_kind: "k".into(),
            action: vec![1, 2, 3],
            scope: Some("s".into()),
            ..Default::default()
        };
        let other_auth = SponsorRequest {
            request_id: "b".into(),
            authentication_type: b"t".to_vec(),
            authentication_payload: vec![9],
            ..base.clone()
        };
        assert_eq!(base.action_digest(), other_auth.action_digest());
        let changed = [
            SponsorRequest {
                action: vec![1, 2],
                ..base.clone()
            },
            SponsorRequest {
                action_kind: "k2".into(),
                ..base.clone()
            },
            SponsorRequest {
                scope: Some("s2".into()),
                ..base.clone()
            },
            SponsorRequest {
                scope: None,
                ..base.clone()
            },
            SponsorRequest {
                action_kind: "k\u{1}".into(),
                action: vec![2, 3],
                ..base.clone()
            },
        ];
        for c in &changed {
            assert_ne!(base.action_digest(), c.action_digest());
        }
    }

    #[test]
    fn a_response_round_trips_each_status() {
        let granted = SponsorResponse {
            request_id: "r".into(),
            status: Status::Granted,
            message: None,
            result: Some(vec![1, 2]),
            code: None,
        };
        let refused = SponsorResponse {
            request_id: "r".into(),
            status: Status::Refused,
            message: Some("credential already used: n".into()),
            result: None,
            code: Some("credential_used".into()),
        };
        let not_submitted = SponsorResponse {
            request_id: "r".into(),
            status: Status::NotSubmitted,
            message: Some("the payer cannot pay".into()),
            result: None,
            code: None,
        };
        let unconfirmed = SponsorResponse {
            request_id: String::new(),
            status: Status::Unconfirmed,
            message: Some("not on chain".into()),
            result: None,
            code: None,
        };
        assert_eq!(
            granted.encode(),
            vec![0x0A, 0x01, b'r', 0x10, 0x01, 0x22, 0x02, 1, 2]
        );
        for resp in [granted, refused, not_submitted, unconfirmed] {
            assert_eq!(SponsorResponse::decode(&resp.encode()).unwrap(), resp);
        }
        assert_eq!(
            SponsorResponse::decode(&[0x0A, 0x01, b'r']).unwrap_err(),
            "missing status"
        );
        assert_eq!(
            SponsorResponse::decode(&[0x0A, 0x01, b'r', 0x10, 0x09]).unwrap_err(),
            "unknown status 9"
        );
    }
}
