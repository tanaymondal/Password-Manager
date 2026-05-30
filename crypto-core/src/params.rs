#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub iterations: u32,
    pub memory_kib: u32,
    pub parallelism: u32,
}

pub const DEFAULT_PARAMS: KdfParams = KdfParams {
    iterations: 3,
    memory_kib: 98304,
    parallelism: 4,
};
