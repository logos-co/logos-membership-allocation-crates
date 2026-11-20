pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

pub fn put_len_field(out: &mut Vec<u8>, field: u64, data: &[u8]) {
    put_varint(out, (field << 3) | 2);
    put_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

pub fn put_varint_field(out: &mut Vec<u8>, field: u64, v: u64) {
    put_varint(out, field << 3);
    put_varint(out, v);
}

fn read_varint(buf: &[u8], i: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *buf.get(*i)?;
        *i += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

#[derive(Clone, Copy)]
pub enum FieldVal<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

pub fn walk_fields<'a, F: FnMut(u64, FieldVal<'a>)>(buf: &'a [u8], mut f: F) -> Result<(), String> {
    let mut i = 0usize;
    while i < buf.len() {
        let key = read_varint(buf, &mut i).ok_or("truncated field key")?;
        let field = key >> 3;
        match key & 7 {
            0 => {
                let v = read_varint(buf, &mut i).ok_or("truncated varint value")?;
                f(field, FieldVal::Varint(v));
            }
            2 => {
                let len = read_varint(buf, &mut i).ok_or("truncated length")? as usize;
                let end = i.checked_add(len).ok_or("length overflow")?;
                if end > buf.len() {
                    return Err("length exceeds buffer".into());
                }
                f(field, FieldVal::Bytes(&buf[i..end]));
                i = end;
            }
            w => return Err(format!("unsupported wire type {w}")),
        }
    }
    Ok(())
}

pub fn as_slice(v: FieldVal<'_>) -> &[u8] {
    match v {
        FieldVal::Bytes(b) => b,
        FieldVal::Varint(_) => &[],
    }
}

pub fn as_bytes(v: FieldVal) -> Vec<u8> {
    as_slice(v).to_vec()
}

pub fn as_string(v: FieldVal) -> String {
    match v {
        FieldVal::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        FieldVal::Varint(_) => String::new(),
    }
}

pub fn as_u64(v: FieldVal) -> u64 {
    match v {
        FieldVal::Varint(n) => n,
        FieldVal::Bytes(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_round_trip_and_malformed_frames_fail() {
        let mut out = Vec::new();
        put_len_field(&mut out, 1, b"x");
        put_varint_field(&mut out, 5, 300);
        put_len_field(&mut out, 20, b"c");
        assert_eq!(
            out,
            vec![0x0A, 0x01, b'x', 0x28, 0xAC, 0x02, 0xA2, 0x01, 0x01, b'c']
        );
        let mut seen = Vec::new();
        walk_fields(&out, |f, v| seen.push((f, as_string(v), as_u64(v)))).unwrap();
        assert_eq!(
            seen,
            vec![
                (1, "x".to_string(), 0),
                (5, String::new(), 300),
                (20, "c".to_string(), 0)
            ]
        );
        assert_eq!(
            walk_fields(&[0x0A, 0x05, b'x'], |_, _| {}).unwrap_err(),
            "length exceeds buffer"
        );
        assert_eq!(
            walk_fields(&[0x0D], |_, _| {}).unwrap_err(),
            "unsupported wire type 5"
        );
    }
}
