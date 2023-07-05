use crate::crypto;
use crate::msgs::enums::HashAlgorithm;
use ring;

pub(crate) struct Hash(
    &'static ring::digest::Algorithm,
    HashAlgorithm,
    &'static [u8],
);

pub(crate) static SHA256: Hash = Hash(
    &ring::digest::SHA256,
    HashAlgorithm::SHA256,
    &[
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ],
);
pub(crate) static SHA384: Hash = Hash(
    &ring::digest::SHA384,
    HashAlgorithm::SHA384,
    &[
        0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3,
        0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6,
        0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48,
        0x98, 0xb9, 0x5b,
    ],
);

impl From<ring::digest::Digest> for crypto::hash::Output {
    fn from(val: ring::digest::Digest) -> Self {
        Self::new(val.as_ref())
    }
}

impl crypto::hash::Hash for Hash {
    fn algorithm(&self) -> HashAlgorithm {
        self.1
    }

    fn output_len(&self) -> usize {
        self.0.output_len
    }

    fn start(&self) -> Box<dyn crypto::hash::Context> {
        Box::new(Context(ring::digest::Context::new(self.0)))
    }

    fn compute_empty(&self) -> crypto::hash::Output {
        crypto::hash::Output::new(self.2)
    }

    fn compute(&self, bytes: &[u8]) -> crypto::hash::Output {
        let mut ctx = ring::digest::Context::new(self.0);
        ctx.update(bytes);
        ctx.finish().into()
    }
}

struct Context(ring::digest::Context);

impl crypto::hash::Context for Context {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn fork(&self) -> Box<dyn crypto::hash::Context> {
        Box::new(Self(self.0.clone()))
    }

    fn fork_finish(&self) -> crypto::hash::Output {
        self.0.clone().finish().into()
    }

    fn finish(self: Box<Self>) -> crypto::hash::Output {
        self.0.finish().into()
    }
}
