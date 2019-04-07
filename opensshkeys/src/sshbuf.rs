pub use openssl::bn::BigNum;
use byteorder::{BigEndian, ReadBytesExt};
use std::io;

const MAX_BIGNUM: usize = 16384 / 8;

pub struct SshReader<R> {
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
        match self.stream.read_u8() {
            Ok(n) => Ok(n != 0),
            Err(e) => Err(e)
        }
    }
    pub fn read_u32(&mut self) -> io::Result<u32> {
        self.stream.read_u32::<BigEndian>()
    }
    pub fn read_u64(&mut self) -> io::Result<u64> {
        self.stream.read_u64::<BigEndian>()
    }
    pub fn read_string(&mut self) -> io::Result<Vec<u8>> {
        let length = match self.read_u32()? as usize;
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
}