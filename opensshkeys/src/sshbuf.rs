pub use openssl::bn::{BigNum, BigNumRef};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io;

const MAX_BIGNUM: usize = 16384 / 8;

pub struct SshReader<R: io::Read> {
    stream: R,
}

impl<R: io::Read> SshReader<R> {
    pub fn new(stream: R) -> SshReader<R> {
        SshReader {
            stream: stream
        }
    }
    pub fn read_bytes(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
    pub fn read_bool(&mut self) -> io::Result<bool> {
        let i = self.stream.read_u8()?;
        Ok(i != 0)
    }
    pub fn read_u32(&mut self) -> io::Result<u32> {
        self.stream.read_u32::<BigEndian>()
    }
    pub fn read_u64(&mut self) -> io::Result<u64> {
        self.stream.read_u64::<BigEndian>()
    }
    pub fn read_string(&mut self) -> io::Result<Vec<u8>> {
        let length = self.read_u32()? as usize;
        let mut buf = vec![0u8; length];
        if self.read_bytes(&mut buf)? == length {
            Ok(buf)
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid length"))
        }
    }
    pub fn read_utf8(&mut self) -> io::Result<String> {
        let data = self.read_string()?;
        match String::from_utf8(data) {
            Ok(string) => Ok(string),
            Err(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 sequence"))
        }
    }
    pub fn read_mpint(&mut self) -> io::Result<BigNum> {
        let data = self.read_string()?;

        if data.len() != 0 && data[0] & 0x80 != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Negative Big Number"));
        }
        if (data.len() > MAX_BIGNUM + 1) || (data.len() == MAX_BIGNUM + 1 && data[0] != 0) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Big Number Too Long"));
        }
        // Remove Leading zeros
        let mut i = 0;
        let mut iter = data.iter();
        while let Some(0) = iter.next() {
            i += 1;
        }
        match BigNum::from_slice(&data[i..]) {
            Ok(bn) => Ok(bn),
            Err(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid Big Number"))
        }
    }
    pub fn read_list(&mut self) -> io::Result<Vec<String>> {
        let string = self.read_utf8()?;
        Ok(string.split(',').map(String::from).collect())
    }

    pub fn into_inner(self) -> R {
        self.stream
    }
}

pub struct SshWriter<W: io::Write> {
    stream: W,
}

impl<W: io::Write> SshWriter<W> {
    pub fn new(stream: W) -> SshWriter<W> {
        SshWriter {
            stream: stream
        }
    }
    pub fn write_bytes(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(self.stream.write(buf)?)
    }
    pub fn write_bool(&mut self, value: bool) -> io::Result<()> {
        let i = if value {
            1u8
        } else {
            0u8
        };
        self.stream.write_u8(i)?;
        Ok(())
    }
    pub fn write_u32(&mut self, value: u32) -> io::Result<()> {
        self.stream.write_u32::<BigEndian>(value)?;
        Ok(())
    }
    pub fn write_u64(&mut self, value: u64) -> io::Result<()> {
        self.stream.write_u64::<BigEndian>(value)?;
        Ok(())
    }
    pub fn write_string(&mut self, buf: &[u8]) -> io::Result<()> {
        self.write_u32(buf.len() as u32)?;
        self.write_bytes(buf)?;
        Ok(())
    }
    pub fn write_utf8(&mut self, value: &str) -> io::Result<()> {
        self.write_string(value.as_bytes())?;
        Ok(())
    }
    pub fn write_mpint(&mut self, value: &BigNumRef) -> io::Result<()> {
        let buf = value.to_vec();
        self.write_string(&buf)?;
        Ok(())
    }
    pub fn write_list(&mut self, values: &[&str]) -> io::Result<()> {
        let mut list_str = String::new();
        for s in values {
            if s.contains(",") {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "List elements can't contain ','"));
            }
            if !s.is_ascii() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "List elements should only contain ascii characters"));
            }
            if list_str.len() > 0 {
                list_str.push_str(",");
            }
            list_str.push_str(s);
        }
        self.write_utf8(&list_str)?;
        Ok(())
    }

    pub fn into_inner(self) -> W {
        self.stream
    }
}
