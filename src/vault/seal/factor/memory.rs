//! Aligned Argon2 scratch memory backed by a zeroed word allocation.

use argon2::Block;
use zeroize::Zeroizing;

use crate::vault::{VaultError, VaultResult};

const WORDS_PER_BLOCK: usize = size_of::<Block>() / size_of::<u64>();
const ALIGNMENT_WORDS: usize = align_of::<Block>().div_ceil(size_of::<u64>());
const _: () = assert!(size_of::<Block>() == Block::SIZE);

pub(super) struct Argon2Memory {
    words: Zeroizing<Box<[u64]>>,
}

impl Argon2Memory {
    pub(super) fn new(block_count: usize) -> VaultResult<Self> {
        let words = block_count
            .checked_mul(WORDS_PER_BLOCK)
            .and_then(|words| words.checked_add(ALIGNMENT_WORDS))
            .filter(|words| *words <= isize::MAX as usize / size_of::<u64>())
            .ok_or_else(|| {
                VaultError::Protection("Argon2 scratch memory is too large".to_owned())
            })?;
        // A primitive zero-filled Vec can use the allocator's zeroed-memory
        // path. A Vec<Block> instead clones a 1 KiB default into every slot.
        // Conversion to Box happens before secrets enter the allocation.
        Ok(Self {
            words: Zeroizing::new(vec![0_u64; words].into_boxed_slice()),
        })
    }

    pub(super) fn blocks(&mut self) -> &mut [Block] {
        aligned_blocks(&mut self.words)
    }
}

fn aligned_blocks(words: &mut [u64]) -> &mut [Block] {
    // SAFETY: argon2::Block is documented as 128 u64 words, with 64-byte
    // alignment. All bit patterns are valid, and its size has no padding.
    // The byte view works even where u64 alignment is smaller than its
    // size. align_to_mut supplies the required alignment and exclusive view
    // whose lifetime is bounded by this borrow. The extra alignment words
    // guarantee exactly the requested number of whole blocks regardless
    // of the allocator's starting alignment. Zeroizing retains ownership
    // of and wipes the entire allocation, including prefix/suffix words.
    #[allow(unsafe_code)]
    unsafe {
        let bytes = words.align_to_mut::<u8>().1;
        bytes.align_to_mut::<Block>().1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{Algorithm, Argon2, Params, Version};
    use zeroize::Zeroize as _;

    #[test]
    fn scratch_memory_is_aligned_zeroed_and_fully_wiped() {
        for count in [0, 1, 2, 17, 1024] {
            let mut memory = Argon2Memory::new(count).unwrap();
            let blocks = memory.blocks();
            assert_eq!(blocks.len(), count);
            assert_eq!(blocks.as_ptr().align_offset(align_of::<Block>()), 0);
            for block in blocks {
                assert!(block.as_ref().iter().all(|word| *word == 0));
                block.as_mut().fill(u64::MAX);
            }
            memory.words.zeroize();
            assert!(memory.words.iter().all(|word| *word == 0));
        }
        assert!(Argon2Memory::new(usize::MAX).is_err());
    }

    #[test]
    fn scratch_memory_matches_standard_argon2_derivation() {
        let params = Params::new(8 * 1024, 1, 1, Some(32)).unwrap();
        let mut memory = Argon2Memory::new(params.block_count()).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut expected = Zeroizing::new([0_u8; 32]);
        let mut actual = Zeroizing::new([0_u8; 32]);
        argon2
            .hash_password_into(b"synthetic password", b"synthetic salt", &mut *expected)
            .unwrap();
        argon2
            .hash_password_into_with_memory(
                b"synthetic password",
                b"synthetic salt",
                &mut *actual,
                memory.blocks(),
            )
            .unwrap();
        assert_eq!(actual.as_slice(), expected.as_slice());
    }

    #[test]
    fn block_view_handles_each_word_offset() {
        let count = 3;
        let length = count * WORDS_PER_BLOCK + ALIGNMENT_WORDS;
        let mut words = vec![0_u64; length + ALIGNMENT_WORDS];
        for offset in 0..ALIGNMENT_WORDS {
            let blocks = aligned_blocks(&mut words[offset..offset + length]);
            assert_eq!(blocks.len(), count);
            assert_eq!(blocks.as_ptr().align_offset(align_of::<Block>()), 0);
        }
    }
}
