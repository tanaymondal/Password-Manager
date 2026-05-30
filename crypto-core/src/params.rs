#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub iterations: u32,
    pub memory_kib: u32,
    pub parallelism: u32,
}

pub const DEFAULT_PARAMS: KdfParams = KdfParams {
    iterations: 4,
    memory_kib: 65536,
    parallelism: 4,
};
