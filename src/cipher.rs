use std::str::FromStr;

use self::internal_impl::*;
use crate::error::{Error as OsshError, ErrorKind, OsshResult};

/// Indicate the algorithm used by encryption/decryption
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum Cipher {
    Aes128_Cbc,
    Aes192_Cbc,
    Aes256_Cbc,
    Aes128_Ctr,
    Aes192_Ctr,
    Aes256_Ctr,
    TDes_Cbc,
    Null,
}

impl Cipher {
    /// Encrypt the data
    ///
    /// Mostly used by the internal codes.
    /// Usually you don't need to call it directly.
    pub fn encrypt(self, src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
        use Cipher::*;
        match self {
            Aes128_Cbc => aes128cbc_encrypt(src, key, iv),
            Aes192_Cbc => aes192cbc_encrypt(src, key, iv),
            Aes256_Cbc => aes256cbc_encrypt(src, key, iv),
            Aes128_Ctr => aes128ctr_encrypt(src, key, iv),
            Aes192_Ctr => aes192ctr_encrypt(src, key, iv),
            Aes256_Ctr => aes256ctr_encrypt(src, key, iv),
            TDes_Cbc => tdescbc_encrypt(src, key, iv),
            Null => Ok(src.to_vec()),
        }
    }

    /// Decrypt the data
    ///
    /// Mostly used by the internal codes.
    /// Usually you don't need to call it directly.
    pub fn decrypt(self, src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
        let mut buf = vec![0; self.calc_buffer_len(src.len())];
        let n = self.decrypt_to(&mut buf, src, key, iv)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn decrypt_to(
        self,
        dest: &mut [u8],
        src: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> OsshResult<usize> {
        use Cipher::*;
        match self {
            Aes128_Cbc => aes128cbc_decrypt(dest, src, key, iv),
            Aes192_Cbc => aes192cbc_decrypt(dest, src, key, iv),
            Aes256_Cbc => aes256cbc_decrypt(dest, src, key, iv),
            Aes128_Ctr => aes128ctr_decrypt(dest, src, key, iv),
            Aes192_Ctr => aes192ctr_decrypt(dest, src, key, iv),
            Aes256_Ctr => aes256ctr_decrypt(dest, src, key, iv),
            TDes_Cbc => tdescbc_decrypt(dest, src, key, iv),
            Null => {
                if dest.len() >= src.len() {
                    dest[..src.len()].clone_from_slice(src);
                    Ok(src.len())
                } else {
                    Err(ErrorKind::InvalidLength.into())
                }
            }
        }
    }

    /// Get the required buffer length of the underlying backend
    ///
    /// Different cipher backend have different destination buffer length
    /// requirement. You should make sure the length of `dest` buffer passed to [decrypt_to()](enum.Cipher.html#method.decrypt_to)
    /// is equal to the result of this function.
    ///
    /// ```
    /// # use osshkeys::cipher::Cipher;
    /// # use hex_literal::hex;
    /// let cipher = Cipher::Aes128_Cbc;
    /// let src = hex!("ed58042b83e18d59bde732638136ac0e");
    /// let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    /// let iv = hex!("000102030405060708090a0b0c0d0e0f");
    ///
    /// let mut buf = vec![0; cipher.calc_buffer_len(src.len())];
    /// let n = cipher.decrypt_to(&mut buf, &src, &key, &iv).unwrap();
    /// buf.truncate(n);
    /// ```
    pub fn calc_buffer_len(self, len: usize) -> usize {
        calc_buflen(len, self.block_size())
    }

    /// Return the required key length in bytes
    pub fn key_len(self) -> usize {
        use Cipher::*;
        match self {
            Aes128_Cbc => 16,
            Aes192_Cbc => 24,
            Aes256_Cbc => 32,
            Aes128_Ctr => 16,
            Aes192_Ctr => 24,
            Aes256_Ctr => 32,
            TDes_Cbc => 24,
            Null => 0,
        }
    }

    /// Return the required IV length in bytes
    pub fn iv_len(self) -> usize {
        use Cipher::*;
        match self {
            Aes128_Cbc => 16,
            Aes192_Cbc => 16,
            Aes256_Cbc => 16,
            Aes128_Ctr => 16,
            Aes192_Ctr => 16,
            Aes256_Ctr => 16,
            TDes_Cbc => 8,
            Null => 0,
        }
    }

    /// Return the block size of the algorithm
    pub fn block_size(self) -> usize {
        use Cipher::*;
        match self {
            Aes128_Cbc => 16,
            Aes192_Cbc => 16,
            Aes256_Cbc => 16,
            Aes128_Ctr => 16,
            Aes192_Ctr => 16,
            Aes256_Ctr => 16,
            TDes_Cbc => 8,
            Null => 8,
        }
    }

    /// Return the name using in OpenSSH
    pub fn name(self) -> &'static str {
        use Cipher::*;
        match self {
            Aes128_Cbc => "aes128-cbc",
            Aes192_Cbc => "aes192-cbc",
            Aes256_Cbc => "aes256-cbc",
            Aes128_Ctr => "aes128-ctr",
            Aes192_Ctr => "aes192-ctr",
            Aes256_Ctr => "aes256-ctr",
            TDes_Cbc => "3des-cbc",
            Null => "none",
        }
    }

    /// Return `true` if `Cipher::Null`
    ///
    /// This is a method for check the null cipher easily
    #[inline]
    pub fn is_null(self) -> bool {
        self == Cipher::Null
    }

    /// Return `true` if not `Cipher::Null`
    ///
    /// This is a method to check the null cipher easily
    #[inline]
    pub fn is_some(self) -> bool {
        self != Cipher::Null
    }
}

impl FromStr for Cipher {
    type Err = OsshError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use Cipher::*;
        match s {
            "3des-cbc" => Ok(TDes_Cbc),
            "aes128-cbc" => Ok(Aes128_Cbc),
            "aes192-cbc" => Ok(Aes192_Cbc),
            "aes256-cbc" | "rijndael-cbc@lysator.liu.se" => Ok(Aes256_Cbc),
            "aes128-ctr" => Ok(Aes128_Ctr),
            "aes192-ctr" => Ok(Aes192_Ctr),
            "aes256-ctr" => Ok(Aes256_Ctr),
            "none" => Ok(Null),
            _ => Err(ErrorKind::UnsupportCipher.into()),
        }
    }
}

#[cfg(not(any(feature = "rustcrypto-cipher", feature = "openssl-cipher")))]
compile_error!("No cipher backend is selected! Please enable one cipher backend feature.");

#[cfg(all(feature = "rustcrypto-cipher", feature = "openssl-cipher"))]
compile_error!("Multiple cipher backends are selected! Only one cipher backend is supported.");

#[cfg(feature = "rustcrypto-cipher")]
mod internal_impl {
    use aes::{Aes128, Aes128Ctr, Aes192, Aes192Ctr, Aes256, Aes256Ctr};
    use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
    use cipher::{NewCipher, StreamCipher};
    use des::TdesEde3;

    use crate::error::{ErrorKind, OsshResult};

    type Aes128Cbc = Cbc<Aes128, Pkcs7>;
    type Aes192Cbc = Cbc<Aes192, Pkcs7>;
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;
    type TdesCbc = Cbc<TdesEde3, Pkcs7>;

    fn clone_buffer(dest: &mut [u8], src: &[u8]) -> OsshResult<()> {
        if dest.len() >= src.len() {
            dest[..src.len()].clone_from_slice(src);
            Ok(())
        } else {
            Err(ErrorKind::InvalidLength.into())
        }
    }

    pub fn calc_buflen(len: usize, block_size: usize) -> usize {
        let addi = (block_size - (len % block_size)) % block_size;
        len + addi
    }

    pub fn aes128cbc_encrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
        Ok(Aes128Cbc::new_from_slices(key, iv)?.encrypt_vec(src))
    }
    pub fn aes128cbc_decrypt(
        dest: &mut [u8],
        src: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> OsshResult<usize> {
        clone_buffer(dest, src)?;
        let n = Aes128Cbc::new_from_slices(key, iv)?.decrypt(dest)?.len();
        Ok(n)
    }

    pub fn aes192cbc_encrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
        Ok(Aes192Cbc::new_from_slices(key, iv)?.encrypt_vec(src))
    }
    pub fn aes192cbc_decrypt(
        dest: &mut [u8],
        src: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> OsshResult<usize> {
        clone_buffer(dest, src)?;
        let n = Aes192Cbc::new_from_slices(key, iv)?.decrypt(dest)?.len();
        Ok(n)
    }

    pub fn aes256cbc_encrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
        Ok(Aes256Cbc::new_from_slices(key, iv)?.encrypt_vec(src))
    }
    pub fn aes256cbc_decrypt(
        dest: &mut [u8],
        src: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> OsshResult<usize> {
        clone_buffer(dest, src)?;
        let n = Aes256Cbc::new_from_slices(key, iv)?.decrypt(dest)?.len();
        Ok(n)
    }

    pub fn tdescbc_encrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
        Ok(TdesCbc::new_from_slices(key, iv)?.encrypt_vec(src))
    }
    pub fn tdescbc_decrypt(
        dest: &mut [u8],
        src: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> OsshResult<usize> {
        clone_buffer(dest, src)?;
        let n = TdesCbc::new_from_slices(key, iv)?.decrypt(dest)?.len();
        Ok(n)
    }

    pub fn aes128ctr_encrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
        let mut encrypted = Vec::from(src);
        Aes128Ctr::new_from_slices(key, iv)?.apply_keystream(&mut encrypted);
        Ok(encrypted)
    }
    pub fn aes128ctr_decrypt(
        dest: &mut [u8],
        src: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> OsshResult<usize> {
        clone_buffer(dest, src)?;
        Aes128Ctr::new_from_slices(key, iv)?.apply_keystream(dest);
        Ok(src.len())
    }

    pub fn aes192ctr_encrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
        let mut encrypted = Vec::from(src);
        Aes192Ctr::new_from_slices(key, iv)?.apply_keystream(&mut encrypted);
        Ok(encrypted)
    }
    pub fn aes192ctr_decrypt(
        dest: &mut [u8],
        src: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> OsshResult<usize> {
        clone_buffer(dest, src)?;
        Aes192Ctr::new_from_slices(key, iv)?.apply_keystream(dest);
        Ok(src.len())
    }

    pub fn aes256ctr_encrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
        let mut encrypted = Vec::from(src);
        Aes256Ctr::new_from_slices(key, iv)?.apply_keystream(&mut encrypted);
        Ok(encrypted)
    }
    pub fn aes256ctr_decrypt(
        dest: &mut [u8],
        src: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> OsshResult<usize> {
        clone_buffer(dest, src)?;
        Aes256Ctr::new_from_slices(key, iv)?.apply_keystream(dest);
        Ok(src.len())
    }
}

#[cfg(feature = "openssl-cipher")]
mod internal_impl {
    use openssl::symm::{Cipher, Crypter, Mode};

    use crate::error::OsshResult;

    fn openssl_encrypt(cipher: Cipher, src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
        let mut crypt = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))?;
        let mut buf = vec![0; src.len() + cipher.block_size()];
        let mut n = crypt.update(src, &mut buf)?;
        n += crypt.finalize(&mut buf[n..])?;
        buf.truncate(n);
        Ok(buf)
    }

    fn openssl_decrypt(
        cipher: Cipher,
        mut dest: &mut [u8],
        src: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> OsshResult<usize> {
        let mut crypt = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))?;
        let mut n = crypt.update(src, &mut dest)?;
        n += crypt.finalize(&mut dest[n..])?;
        Ok(n)
    }

    pub fn calc_buflen(len: usize, block_size: usize) -> usize {
        let bs = block_size;
        len + bs
    }

    pub fn aes128cbc_encrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
        openssl_encrypt(Cipher::aes_128_cbc(), src, key, iv)
    }
    pub fn aes128cbc_decrypt(
        dest: &mut [u8],
        src: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> OsshResult<usize> {
        openssl_decrypt(Cipher::aes_128_cbc(), dest, src, key, iv)
    }

    pub fn aes192cbc_encrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
        openssl_encrypt(Cipher::aes_192_cbc(), src, key, iv)
    }
    pub fn aes192cbc_decrypt(
        dest: &mut [u8],
        src: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> OsshResult<usize> {
        openssl_decrypt(Cipher::aes_192_cbc(), dest, src, key, iv)
    }

    pub fn aes256cbc_encrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
        openssl_encrypt(Cipher::aes_256_cbc(), src, key, iv)
    }
    pub fn aes256cbc_decrypt(
        dest: &mut [u8],
        src: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> OsshResult<usize> {
        openssl_decrypt(Cipher::aes_256_cbc(), dest, src, key, iv)
    }

    pub fn tdescbc_encrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
        openssl_encrypt(Cipher::des_ede3_cbc(), src, key, iv)
    }
    pub fn tdescbc_decrypt(
        dest: &mut [u8],
        src: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> OsshResult<usize> {
        openssl_decrypt(Cipher::des_ede3_cbc(), dest, src, key, iv)
    }

    pub fn aes128ctr_encrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
        openssl_encrypt(Cipher::aes_128_ctr(), src, key, iv)
    }
    pub fn aes128ctr_decrypt(
        dest: &mut [u8],
        src: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> OsshResult<usize> {
        openssl_decrypt(Cipher::aes_128_ctr(), dest, src, key, iv)
    }

    pub fn aes192ctr_encrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
        openssl_encrypt(Cipher::aes_192_ctr(), src, key, iv)
    }
    pub fn aes192ctr_decrypt(
        dest: &mut [u8],
        src: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> OsshResult<usize> {
        openssl_decrypt(Cipher::aes_192_ctr(), dest, src, key, iv)
    }

    pub fn aes256ctr_encrypt(src: &[u8], key: &[u8], iv: &[u8]) -> OsshResult<Vec<u8>> {
        openssl_encrypt(Cipher::aes_256_ctr(), src, key, iv)
    }
    pub fn aes256ctr_decrypt(
        dest: &mut [u8],
        src: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> OsshResult<usize> {
        openssl_decrypt(Cipher::aes_256_ctr(), dest, src, key, iv)
    }
}
