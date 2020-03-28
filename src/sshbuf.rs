use byteorder::{BigEndian, WriteBytesExt};
use cryptovec::CryptoVec;
pub use openssl::bn::{BigNum, BigNumRef};
use std::io;
use std::io::Result;
use std::str;
use zeroize::{Zeroize, Zeroizing};

const MAX_BIGNUM: usize = 16384 / 8;

/// [io::Read](https://doc.rust-lang.org/std/io/trait.Read.html) extension to read ssh data
pub trait SshReadExt {
    /// Read a byte and convert it to boolean
    ///
    /// By definition, all non-zero value would be interpreted as true.
    fn read_bool(&mut self) -> Result<bool>;

    fn read_uint8(&mut self) -> io::Result<u8>;

    /// Read 32 bits unsigned integer in big endian
    fn read_uint32(&mut self) -> io::Result<u32>;

    /// Read 64 bits unsigned integer in big endian
    fn read_uint64(&mut self) -> io::Result<u64>;

    /// Read bytes array or string
    ///
    /// Before the binary string, there is a 32 bits unsigned integer to indicate the length of the data,
    /// and the binary string is **NOT** null-terminating.
    fn read_string(&mut self) -> io::Result<Vec<u8>>;

    /// Read UTF-8 string
    ///
    /// This actually does the same thing as [read_string()](trait.SshReadExt.html#tymethod.read_string) does.
    /// But it also convert the binary data to [String](https://doc.rust-lang.org/std/string/struct.String.html).
    fn read_utf8(&mut self) -> io::Result<String>;

    /// Read multiple precision integer
    ///
    /// Although it can contain negative number, but we don't support it currently.
    /// Integers which is longer than 16384 bits are also not supporting.
    fn read_mpint(&mut self) -> io::Result<BigNum>;

    /*
    /// Read name-list
    ///
    /// It is a list representing in an ASCII string separated by the `,` charactor.
    fn read_list<B: FromIterator<String>>(&mut self) -> io::Result<B>;
    */
}

impl<R: io::Read + ?Sized> SshReadExt for R {
    fn read_bool(&mut self) -> io::Result<bool> {
        let i = Zeroizing::new(self.read_uint8()?);
        Ok(*i != 0)
    }

    fn read_uint8(&mut self) -> io::Result<u8> {
        let mut buf = Zeroizing::new([0u8; 1]);
        self.read_exact(&mut *buf)?;
        Ok(buf[0])
    }

    fn read_uint32(&mut self) -> io::Result<u32> {
        let mut buf = Zeroizing::new([0u8; 4]);
        self.read_exact(&mut *buf)?;
        Ok(u32::from_be_bytes(*buf))
    }

    fn read_uint64(&mut self) -> io::Result<u64> {
        let mut buf = Zeroizing::new([0u8; 8]);
        self.read_exact(&mut *buf)?;
        Ok(u64::from_be_bytes(*buf))
    }

    fn read_string(&mut self) -> io::Result<Vec<u8>> {
        let len = self.read_uint32()? as usize;
        let mut buf = vec![0u8; len];
        match self.read_exact(buf.as_mut_slice()) {
            Ok(_) => Ok(buf),
            Err(e) => {
                buf.zeroize();
                Err(e)
            }
        }
    }

    fn read_utf8(&mut self) -> io::Result<String> {
        let mut buf = self.read_string()?;
        // Make data be zeroed even an error occurred
        // So we cannot directly use `String::from_utf8()`
        match str::from_utf8(&buf) {
            Ok(_) => unsafe {
                // We have checked the string using `str::from_utf8()`
                // To avoid memory copy, just use `from_utf8_unchecked()`
                Ok(String::from_utf8_unchecked(buf))
            },
            Err(_) => {
                buf.zeroize();
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid UTF-8 sequence",
                ))
            }
        }
    }

    fn read_mpint(&mut self) -> io::Result<BigNum> {
        let data = Zeroizing::new(self.read_string()?);
        to_bignum(&data)
    }
    /*
    fn read_list<B: FromIterator<String>>(&mut self) -> io::Result<B> {
        let string = self.read_utf8()?;
        Ok(string.split(',').map(String::from).collect())
    }
    */
}

// --------------------------
// ---- Helper Functions ----
// --------------------------
fn to_bignum(data: &[u8]) -> io::Result<BigNum> {
    if !data.is_empty() && data[0] & 0x80 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Negative Big Number",
        ));
    }
    if (data.len() > MAX_BIGNUM + 1) || (data.len() == MAX_BIGNUM + 1 && data[0] != 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Big Number Too Long",
        ));
    }
    // Remove Leading zeros
    let mut i = 0;
    let mut iter = data.iter();
    while let Some(0) = iter.next() {
        i += 1;
    }
    match BigNum::from_slice(&data[i..]) {
        Ok(bn) => Ok(bn),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid Big Number",
        )),
    }
}

/// [io::Write](https://doc.rust-lang.org/std/io/trait.Write.html) extension to read ssh data
pub trait SshWriteExt {
    /// Convert boolean to one byte and write it
    ///
    /// By definition, **false** should be **0** and **true** should be **1**. Any other value is not allowed.
    fn write_bool(&mut self, value: bool) -> io::Result<()>;

    /// Write 32 bits unsigned integer in big endian
    fn write_uint32(&mut self, value: u32) -> io::Result<()>;

    /// Write 64 bits unsigned integer in big endian
    fn write_uint64(&mut self, value: u64) -> io::Result<()>;

    /// Write binary string data
    ///
    /// Before the binary string, there is a 32 bits unsigned integer to indicate the length of the data,
    /// and the binary string is **NOT** null-terminating.
    fn write_string(&mut self, buf: &[u8]) -> io::Result<()>;

    /// Write UTF-8 string
    ///
    /// Convert the string into bytes array and write it using [write_string()](trait.SshWriteExt.html#tymethod.write_string).
    fn write_utf8(&mut self, value: &str) -> io::Result<()>;

    /// Write multiple precision integer
    ///
    /// Convert the integer into bytes array and write it.
    fn write_mpint(&mut self, value: &BigNumRef) -> io::Result<()>;

    /// Write name-list
    ///
    /// Each entry must meets the following rules:
    /// - not empty string
    /// - not containing the `,` (comma) charactor
    /// - not containing the `\0` (null) charactor
    /// - being a valid ASCII string
    fn write_list<S: AsRef<str>, I: IntoIterator<Item = S>>(&mut self, values: I)
        -> io::Result<()>;
}

impl<W: io::Write + ?Sized> SshWriteExt for W {
    fn write_bool(&mut self, value: bool) -> io::Result<()> {
        let i = if value { 1u8 } else { 0u8 };
        self.write_u8(i)?;
        Ok(())
    }
    fn write_uint32(&mut self, value: u32) -> io::Result<()> {
        self.write_u32::<BigEndian>(value)?;
        Ok(())
    }
    fn write_uint64(&mut self, value: u64) -> io::Result<()> {
        self.write_u64::<BigEndian>(value)?;
        Ok(())
    }
    fn write_string(&mut self, buf: &[u8]) -> io::Result<()> {
        self.write_uint32(buf.len() as u32)?;
        self.write_all(buf)?;
        Ok(())
    }
    fn write_utf8(&mut self, value: &str) -> io::Result<()> {
        self.write_string(value.as_bytes())?;
        Ok(())
    }
    fn write_mpint(&mut self, value: &BigNumRef) -> io::Result<()> {
        let mut buf = vec![0x00u8];
        buf.append(&mut value.to_vec());
        // Add a zero byte to make the intgeter unsigned
        if (buf[1] & 0x80) > 0 {
            self.write_string(&buf[..])
        } else {
            self.write_string(&buf[1..])
        }
    }
    fn write_list<S: AsRef<str>, I: IntoIterator<Item = S>>(
        &mut self,
        values: I,
    ) -> io::Result<()> {
        let mut list_str = String::new();
        for s in values {
            let s = s.as_ref();
            if s.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "List elements shouldn't be empty",
                ));
            }
            if s.contains(',') || s.contains('\0') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "List elements can't contain ',' or '\\0'",
                ));
            }
            if !s.is_ascii() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "List elements should only contain ascii characters",
                ));
            }
            if !list_str.is_empty() {
                list_str.push_str(",");
            }
            list_str.push_str(s);
        }
        self.write_utf8(&list_str)?;
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct SshBuf {
    read_pos: usize,
    buf: CryptoVec,
}

impl SshBuf {
    pub fn new() -> SshBuf {
        SshBuf {
            read_pos: 0,
            buf: CryptoVec::new(),
        }
    }

    pub fn with_vec(v: CryptoVec) -> SshBuf {
        SshBuf {
            read_pos: 0,
            buf: v,
        }
    }

    pub fn position(&self) -> usize {
        self.read_pos
    }

    pub fn set_position(&mut self, offset: usize) {
        if offset > self.buf.len() {
            panic!("Offset exceed length");
        }
        self.read_pos = offset;
    }

    pub fn into_inner(self) -> CryptoVec {
        self.buf
    }

    pub fn get_ref(&self) -> &CryptoVec {
        &self.buf
    }
}

impl io::Read for SshBuf {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.read_pos >= self.buf.len() {
            return Ok(0);
        }
        let n = self.buf.write_all_from(self.read_pos, buf)?;
        self.read_pos += n;
        Ok(n)
    }
}

/*
impl SshReadExt for SshBuf {
    fn read_bool(&mut self) -> io::Result<bool> {
        let i = Zeroizing::new(self.read_uint8()?);
        Ok(*i != 0)
    }

    fn read_uint8(&mut self) -> io::Result<u8> {
        let buf = self.buf[self.read_pos];
        self.read_pos += 1;
        Ok(buf)
    }

    fn read_uint32(&mut self) -> io::Result<u32> {
        let mut buf = Zeroizing::new([0u8; 4]);
        self.read_pos += self.buf.write_all_from(self.read_pos, buf.as_mut())?;
        Ok(u32::from_be_bytes(*buf))
    }

    fn read_uint64(&mut self) -> io::Result<u64> {
        let mut buf = Zeroizing::new([0u8; 8]);
        self.read_pos += self.buf.write_all_from(self.read_pos, buf.as_mut())?;
        Ok(u64::from_be_bytes(*buf))
    }

    fn read_string(&mut self) -> io::Result<Vec<u8>> {
        let len = self.read_uint32()? as usize;
        let mut buf = vec![0u8; len];
        let rl = self.buf.write_all_from(self.read_pos, buf.as_mut_slice())?;
        self.read_pos += rl;
        if rl != len {
            buf.zeroize();
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(buf)
    }

    fn read_utf8(&mut self) -> io::Result<String> {
        let buf = self.read_string()?;
        // Make data be zeroed even an error occurred
        // So we cannot directly use `String::from_utf8()`
        match str::from_utf8(&buf) {
            Ok(_) => unsafe {
                // We have checked the string using `str::from_utf8()`
                // To avoid memory copy, just use `from_utf8_unchecked()`
                Ok(String::from_utf8_unchecked(buf))
            },
            Err(_) => {
                buf.zeroize();
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid UTF-8 sequence",
                ))
            }
        }
    }

    fn read_mpint(&mut self) -> io::Result<BigNum> {
        let buf = Zeroizing::new(self.read_string()?);
        to_bignum(&buf)
    }
}
*/
