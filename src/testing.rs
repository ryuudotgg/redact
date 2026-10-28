pub struct Fake(pub u64);

impl Fake {
    pub fn take(&mut self, alphabet: &[u8], count: usize) -> String {
        (0..count)
            .map(|_| {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                let index = usize::try_from(self.0 % alphabet.len() as u64)
                    .expect("an index fits in usize");

                char::from(alphabet[index])
            })
            .collect()
    }
}

pub const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
pub const URL_SAFE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
pub const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
pub const DIGITS: &[u8] = b"0123456789";

pub fn github_token(seed: u64) -> String {
    ["gh", "p_", &Fake(seed).take(ALNUM, 36)].concat()
}

pub fn password(seed: u64) -> String {
    let mut fake = Fake(seed);
    [&fake.take(ALNUM, 10), "\\q", &fake.take(ALNUM, 6)].concat()
}
