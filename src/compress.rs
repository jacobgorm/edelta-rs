use std::io::{self, Cursor};

pub trait Compressor {
    fn compress(&self, data: &[u8]) -> io::Result<Vec<u8>>;
    fn decompress(&self, data: &[u8]) -> io::Result<Vec<u8>>;
}

#[allow(dead_code)]
pub struct NullCompressor;

impl Compressor for NullCompressor {
    fn compress(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        Ok(data.to_vec())
    }

    fn decompress(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        Ok(data.to_vec())
    }
}

pub struct ZstdCompressor {
    level: i32,
}

impl ZstdCompressor {
    pub fn new(level: i32) -> Self {
        Self { level }
    }
}

impl Default for ZstdCompressor {
    fn default() -> Self {
        Self::new(19)
    }
}

impl Compressor for ZstdCompressor {
    fn compress(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        zstd::encode_all(Cursor::new(data), self.level)
    }

    fn decompress(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        zstd::decode_all(Cursor::new(data))
    }
}
