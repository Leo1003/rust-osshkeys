use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
pub use openssl::bn::{BigNum, BigNumRef};
use std::io;
use std::io::Result;
use std::iter::FromIterator;
use std::str;
use zeroize::{Zeroize, Zeroizing};

const MAX_BIGNUM: usize = 16384 / 8;

/// [io::Read](https://doc.rust-lang.org/std/io/trait.Read.html) extension to read ssh data
pub trait SshReadExt {
    /// Read a byte and convert it to boolean
    ///
    /// By definition, all non-zero value would be interpreted as true.
    fn read_bool(&mut self) -> Result<bool>;

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

    /// Read name-list
    ///
    /// It is a list representing in an ASCII string separated by the `,` charactor.
    fn read_list<B: FromIterator<String>>(&mut self) -> io::Result<B>;
}

impl<R: io::Read + ?Sized> SshReadExt for R {
    fn read_bool(&mut self) -> io::Result<bool> {
        let i = self.read_u8()?;
        Ok(i != 0)
    }
    fn read_uint32(&mut self) -> io::Result<u32> {
        self.read_u32::<BigEndian>()
    }
    fn read_uint64(&mut self) -> io::Result<u64> {
        self.read_u64::<BigEndian>()
    }
    fn read_string(&mut self) -> io::Result<Vec<u8>> {
        let length = self.read_uint32()? as usize;
        let mut buf = vec![0u8; length];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
    fn read_utf8(&mut self) -> io::Result<String> {
        let data = self.read_string()?;
        match String::from_utf8(data) {
            Ok(string) => Ok(string),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid UTF-8 sequence",
            )),
        }
    }
    fn read_mpint(&mut self) -> io::Result<BigNum> {
        let data = self.read_string()?;
        to_bignum(&data)
    }
    fn read_list<B: FromIterator<String>>(&mut self) -> io::Result<B> {
        let string = self.read_utf8()?;
        Ok(string.split(',').map(String::from).collect())
    }
}

/// [io::Read](https://doc.rust-lang.org/std/io/trait.Read.html) extension to securely read ssh data
///
/// This trait should behave as same as [SshReadExt](trait.SshReadExt.html), but it should not left any data in memory.
///
/// For details, please view [SshReadExt](trait.SshReadExt.html) page.
pub trait ZeroizeReadExt {
    fn read_bool_zeroize(&mut self) -> Result<Zeroizing<bool>>;
    fn read_uint8_zeroize(&mut self) -> io::Result<Zeroizing<u8>>;
    fn read_uint32_zeroize(&mut self) -> io::Result<Zeroizing<u32>>;
    fn read_uint64_zeroize(&mut self) -> io::Result<Zeroizing<u64>>;
    fn read_string_zeroize(&mut self) -> io::Result<Zeroizing<Vec<u8>>>;
    fn read_utf8_zeroize(&mut self) -> io::Result<Zeroizing<String>>;
    fn read_mpint_zeroize(&mut self) -> io::Result<BigNum>;
    fn read_list_zeroize<B: FromIterator<String> + Zeroize>(&mut self) -> io::Result<Zeroizing<B>>;
}

impl<R: io::Read + ?Sized> ZeroizeReadExt for R {
    fn read_bool_zeroize(&mut self) -> Result<Zeroizing<bool>> {
        let i = self.read_uint8_zeroize()?;
        Ok(Zeroizing::new(*i != 0))
    }
    fn read_uint8_zeroize(&mut self) -> io::Result<Zeroizing<u8>> {
        let mut buf = Zeroizing::new([0u8; 1]);
        self.read_exact(&mut *buf)?;
        Ok(Zeroizing::new(buf[0]))
    }
    fn read_uint32_zeroize(&mut self) -> io::Result<Zeroizing<u32>> {
        let mut buf = Zeroizing::new([0u8; 4]);
        self.read_exact(&mut *buf)?;
        Ok(Zeroizing::new(BigEndian::read_u32(&*buf)))
    }
    fn read_uint64_zeroize(&mut self) -> io::Result<Zeroizing<u64>> {
        let mut buf = Zeroizing::new([0u8; 8]);
        self.read_exact(&mut *buf)?;
        Ok(Zeroizing::new(BigEndian::read_u64(&*buf)))
    }
    fn read_string_zeroize(&mut self) -> io::Result<Zeroizing<Vec<u8>>> {
        let length = self.read_uint32_zeroize()?;
        let mut buf = Zeroizing::new(vec![0u8; *length as usize]);
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
    fn read_utf8_zeroize(&mut self) -> io::Result<Zeroizing<String>> {
        let data = self.read_string_zeroize()?;
        // Make data be zeroed even an error occurred
        match str::from_utf8(&data) {
            Ok(s) => Ok(Zeroizing::new(String::from(s))),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid UTF-8 sequence",
            )),
        }
    }
    fn read_mpint_zeroize(&mut self) -> io::Result<BigNum> {
        let data = self.read_string_zeroize()?;
        to_bignum(&data)
    }
    fn read_list_zeroize<B: FromIterator<String> + Zeroize>(&mut self) -> io::Result<Zeroizing<B>> {
        let string = self.read_utf8_zeroize()?;
        Ok(Zeroizing::new(
            string.split(',').map(String::from).collect(),
        ))
    }
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
