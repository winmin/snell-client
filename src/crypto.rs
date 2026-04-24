use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes128Gcm;
use anyhow::{bail, Result};
use zeroize::Zeroize;

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
const AES_KEY_LEN: usize = 16;
const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

static ARGON2_PARAMS: std::sync::LazyLock<argon2::Params> =
    std::sync::LazyLock::new(|| argon2::Params::new(8, 3, 1, Some(KEY_LEN)).unwrap());

pub fn derive_key(psk: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        ARGON2_PARAMS.clone(),
    );
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(psk.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("argon2: {}", e))?;
    Ok(key)
}

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    salt
}

pub struct AeadCipher {
    cipher: Aes128Gcm,
    nonce: [u8; NONCE_LEN],
}

impl Drop for AeadCipher {
    fn drop(&mut self) {
        self.nonce.zeroize();
    }
}

impl AeadCipher {
    pub fn new(key: &mut [u8; KEY_LEN]) -> Self {
        let aes_key: [u8; AES_KEY_LEN] = key[..AES_KEY_LEN].try_into().unwrap();
        let cipher = Aes128Gcm::new((&aes_key).into());
        key.zeroize();
        Self {
            cipher,
            nonce: [0u8; NONCE_LEN],
        }
    }

    #[inline]
    fn increment_nonce(&mut self) {
        for b in self.nonce.iter_mut() {
            let (val, overflow) = b.overflowing_add(1);
            *b = val;
            if !overflow {
                return;
            }
        }
    }

    pub fn encrypt_in_place(&mut self, buf: &mut Vec<u8>) -> Result<()> {
        let nonce = GenericArray::from_slice(&self.nonce);
        self.cipher
            .encrypt_in_place(nonce, b"", buf)
            .map_err(|_| anyhow::anyhow!("encrypt failed"))?;
        self.increment_nonce();
        Ok(())
    }

    pub fn decrypt_in_place(&mut self, buf: &mut Vec<u8>) -> Result<()> {
        if buf.len() < TAG_LEN {
            bail!("ciphertext too short");
        }
        let nonce = GenericArray::from_slice(&self.nonce);
        self.cipher
            .decrypt_in_place(nonce, b"", buf)
            .map_err(|_| anyhow::anyhow!("decrypt failed"))?;
        self.increment_nonce();
        Ok(())
    }
}
