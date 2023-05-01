pub type BlockHash = Vec<u8>;

use std::time::{ SystemTime, UNIX_EPOCH };

pub fn now () -> u128 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
    ;

    duration.as_secs() as u128 * 1000 + duration.subsec_millis() as u128
}

pub fn u32_bytes (u: &u32) -> [u8; 4] {
    [
        (u >> 8 * 0x0) as u8,
        (u >> 8 * 0x1) as u8,
        (u >> 8 * 0x2) as u8,
        (u >> 8 * 0x3) as u8,
    ]
}

pub fn u64_bytes (u: &u64) -> [u8; 8] {
    [
        (u >> 8 * 0x0) as u8,
        (u >> 8 * 0x1) as u8,
        (u >> 8 * 0x2) as u8,
        (u >> 8 * 0x3) as u8,

        (u >> 8 * 0x4) as u8,
        (u >> 8 * 0x5) as u8,
        (u >> 8 * 0x6) as u8,
        (u >> 8 * 0x7) as u8,
    ]
}

pub fn u128_bytes (u: &u128) -> [u8; 16] {
    [
        (u >> 8 * 0x0) as u8,
        (u >> 8 * 0x1) as u8,
        (u >> 8 * 0x2) as u8,
        (u >> 8 * 0x3) as u8,

        (u >> 8 * 0x4) as u8,
        (u >> 8 * 0x5) as u8,
        (u >> 8 * 0x6) as u8,
        (u >> 8 * 0x7) as u8,

        (u >> 8 * 0x8) as u8,
        (u >> 8 * 0x9) as u8,
        (u >> 8 * 0xa) as u8,
        (u >> 8 * 0xb) as u8,

        (u >> 8 * 0xc) as u8,
        (u >> 8 * 0xd) as u8,
        (u >> 8 * 0xe) as u8,
        (u >> 8 * 0xf) as u8,
    ]
}


pub struct MerkleTree<H = DefaultHasher> {
    hasher: H,
    nodes: Vec<Hash>,
    count_internal_nodes: usize,
    count_leaves: usize,
}

fn hash_leaf<T, H>(value: &T, hasher: &mut H) -> Hash
    where T: AsBytes,
          H: Digest
{
    let mut result = vec![0u8; hasher.output_bits() / 8];

    hasher.reset();
    hasher.input(&[LEAF_SIG]);
    hasher.input(value.as_bytes());
    hasher.result(result.as_mut_slice());

    result
}

fn hash_internal_node<H>(left: &Hash, right: Option<&Hash>, hasher: &mut H) -> Hash
    where H: Digest
{
    let mut result = vec![0u8; hasher.output_bits() / 8];

    hasher.reset();
    hasher.input(&[INTERNAL_SIG]);
    hasher.input(left.as_slice());
    if let Some(r) = right {
        hasher.input(r.as_slice());
    } else {
        // if there is no right node, we hash left with itself
        hasher.input(left.as_slice());
    }
    hasher.result(result.as_mut_slice());

    result
}

fn build_upper_level<H>(nodes: &[Hash], hasher: &mut H) -> Vec<Hash>
    where H: Digest
{
    let mut row = Vec::with_capacity((nodes.len() + 1) / 2);
    let mut i = 0;
    while i < nodes.len() {
        if i + 1 < nodes.len() {
            row.push(hash_internal_node(&nodes[i], Some(&nodes[i + 1]), hasher));
            i += 2;
        } else {
            row.push(hash_internal_node(&nodes[i], None, hasher));
            i += 1;
        }
    }

    if row.len() > 1 && row.len() % 2 != 0 {
        let last_node = row.last().unwrap().clone();
        row.push(last_node);
    }

    row
}

fn build_internal_nodes<H>(nodes: &mut Vec<Hash>, count_internal_nodes: usize, hasher: &mut H)
    where H: Digest
{
    let mut parents = build_upper_level(&nodes[count_internal_nodes..], hasher);

    let mut upper_level_start = count_internal_nodes - parents.len();
    let mut upper_level_end = upper_level_start + parents.len();
    nodes[upper_level_start..upper_level_end].clone_from_slice(&parents);

    while parents.len() > 1 {
        parents = build_upper_level(parents.as_slice(), hasher);

        upper_level_start -= parents.len();
        upper_level_end = upper_level_start + parents.len();
        nodes[upper_level_start..upper_level_end].clone_from_slice(&parents);
    }

    nodes[0] = parents.remove(0);
}

fn calculate_internal_nodes_count(count_leaves: usize) -> usize {
    utils::next_power_of_2(count_leaves) - 1
}

fn _build_from_leaves_with_hasher<H>(leaves: &[Hash], mut hasher: H) -> MerkleTree<H>
    where H: Digest
{
    let count_leaves = leaves.len();
    let count_internal_nodes = calculate_internal_nodes_count(count_leaves);
    let mut nodes = vec![Vec::new(); count_internal_nodes + count_leaves];

    // copy leafs
    nodes[count_internal_nodes..].clone_from_slice(leaves);

    build_internal_nodes(&mut nodes, count_internal_nodes, &mut hasher);

    MerkleTree {
        nodes: nodes,
        count_internal_nodes: count_internal_nodes,
        count_leaves: count_leaves,
        hasher: hasher,
    }
}

impl<H> MerkleTree<H> {
    /// Constructs a tree from values of data. Data could be anything as long as it could be
    /// represented as bytes array.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let block = "Hello World";
    /// let _t: MerkleTree = MerkleTree::build(&[block, block]);
    /// ```
    pub fn build<T>(values: &[T]) -> MerkleTree<H>
        where H: Digest + Default,
              T: AsBytes
    {
        let hasher = Default::default();
        MerkleTree::build_with_hasher(values, hasher)
    }

    /// Constructs a tree from values of data. Data could be anything as long as it could be
    /// represented as bytes array.
    ///
    /// Hasher could be any object, which implements `crypto::digest::Digest` trait. You could
    /// write your own hasher if you want specific behaviour (e.g. double SHA256).
    ///
    /// # Examples
    ///
    /// ```
    /// # #[macro_use] extern crate crypto;
    /// # #[macro_use] extern crate merkle_tree;
    /// # fn main() {
    ///     use merkle_tree::MerkleTree;
    ///     use crypto::sha2::Sha512;
    ///     type MT = MerkleTree<Sha512>;
    ///
    ///     let block = "Hello World";
    ///     let _t: MT = MT::build_with_hasher(&[block, block], Sha512::new());
    /// }
    /// ```
    pub fn build_with_hasher<T>(values: &[T], mut hasher: H) -> MerkleTree<H>
        where H: Digest,
              T: AsBytes
    {
        let count_leaves = values.len();
        /*assert!(count_leaves > 1,
                format!("expected more then 1 value, received "));*/

        let leaves: Vec<Hash> = values.iter().map(|v| hash_leaf(v, &mut hasher)).collect();

        _build_from_leaves_with_hasher(leaves.as_slice(), hasher)
    }

    /// Constructs a tree from its leaves.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let block = "Hello World";
    /// let t1: MerkleTree = MerkleTree::build(&[block, block]);
    ///
    /// let t2: MerkleTree = MerkleTree::build_from_leaves(t1.leaves());
    ///
    /// assert_eq!(t1.root_hash(), t2.root_hash());
    /// ```
    pub fn build_from_leaves(leaves: &[Hash]) -> MerkleTree<H>
        where H: Digest + Default
    {
        let hasher = Default::default();
        MerkleTree::build_from_leaves_with_hasher(leaves, hasher)
    }

    /// Constructs a tree from its leaves.
    ///
    /// Hasher could be any object, which implements `crypto::digest::Digest` trait. You could
    /// write your own hasher if you want specific behaviour (e.g. double SHA256).
    ///
    /// # Examples
    ///
    /// ```
    /// # #[macro_use] extern crate crypto;
    /// # #[macro_use] extern crate merkle_tree;
    /// # fn main() {
    ///     use merkle_tree::MerkleTree;
    ///     use crypto::sha2::Sha512;
    ///     type MT = MerkleTree<Sha512>;
    ///
    ///     let block = "Hello World";
    ///     let t1: MT = MT::build_with_hasher(&[block, block], Sha512::new());
    ///
    ///     let t2: MT = MT::build_from_leaves_with_hasher(t1.leaves(), Sha512::new());
    ///
    ///     assert_eq!(t1.root_hash(), t2.root_hash());
    /// }
    /// ```
    pub fn build_from_leaves_with_hasher(leaves: &[Hash], hasher: H) -> MerkleTree<H>
        where H: Digest
    {
        let count_leaves = leaves.len();
        /*assert!(count_leaves > 1,
                format!("expected more then 1 leaf, received {}", count_leaves));*/

        _build_from_leaves_with_hasher(leaves, hasher)
    }

    /// Returns the root hash of the tree.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let block = "Hello World";
    /// let t: MerkleTree = MerkleTree::build(&[block, block]);
    ///
    /// assert!(t.root_hash().len() > 0);
    /// ```
    pub fn root_hash(&self) -> &Hash {
        &self.nodes[0]
    }

    /// Returns root hash of the tree as a string.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let block = "Hello World";
    /// let t: MerkleTree = MerkleTree::build(&[block, block]);
    ///
    /// assert_ne!("", t.root_hash_str());
    /// ```
    pub fn root_hash_str(&self) -> String {
        use rustc_serialize::hex::ToHex;
        self.nodes[0].as_slice().to_hex()
    }

    /// Returns the leaves of the tree.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let block = "Hello World";
    /// let t: MerkleTree = MerkleTree::build(&[block, block]);
    ///
    /// assert_eq!(2, t.leaves().len());
    /// ```
    pub fn leaves(&self) -> &[Hash] {
        &self.nodes[self.count_internal_nodes..]
    }

    /// Verify value by comparing its hash against the one in the tree. `position` must not
    /// exceed count of leaves and starts at 0.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let block1 = "Hello World";
    /// let block2 = "Bye, bye";
    /// let mut t: MerkleTree = MerkleTree::build(&[block1, block2]);
    ///
    /// assert!(t.verify(0, &block1));
    /// assert!(!t.verify(0, &block2));
    /// ```
    pub fn verify<T>(&mut self, position: usize, value: &T) -> bool
        where H: Digest,
              T: AsBytes
    {
        assert!(position < self.count_leaves,
                "position does not relate to any leaf");

        self.nodes[self.count_internal_nodes + position].as_slice() ==
        hash_leaf(value, &mut self.hasher).as_slice()
    }
}

/// The default [`Hasher`] used by [`MerkleTree`].
#[derive(Copy, Clone)]
pub struct DefaultHasher(Sha256);

impl DefaultHasher {
    /// Creates a new `DefaultHasher`.
    pub fn new() -> DefaultHasher {
        DefaultHasher(Sha256::new())
    }
}

/// Implementation of the `Default` trait from std library
impl Default for DefaultHasher {
    /// Creates a new `DefaultHasher` using [`DefaultHasher::new`]. See
    /// [`DefaultHasher::new`] documentation for more information.
    ///
    /// [`DefaultHasher::new`]: #method.new
    fn default() -> DefaultHasher {
        DefaultHasher::new()
    }
}

/// Implementation of the `Digest` trait from crypto library for our [`DefaultHasher`]
impl Digest for DefaultHasher {
    #[inline]
    fn input(&mut self, d: &[u8]) {
        self.0.input(d)
    }

    #[inline]
    fn result(&mut self, out: &mut [u8]) {
        self.0.result(out)
    }

    #[inline]
    fn reset(&mut self) {
        self.0.reset()
    }

    #[inline]
    fn output_bits(&self) -> usize {
        self.0.output_bits()
    }

    #[inline]
    fn block_size(&self) -> usize {
        self.0.block_size()
    }
}

impl fmt::Debug for DefaultHasher {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Sha256 does not implement Display or Debug traits
        write!(f, "DefaultHasher {{ Sha256 }}")
    }
}

/// [`AsBytes`] is implemeted for types which are given as values to
/// [`MerkleTree::build`] method.
pub trait AsBytes {
    /// Converts value into the byte slice.
    fn as_bytes(&self) -> &[u8];
}

impl<'a> AsBytes for &'a str {
    fn as_bytes(&self) -> &[u8] {
        str::as_bytes(self)
    }
}

impl AsBytes for String {
    fn as_bytes(&self) -> &[u8] {
        String::as_bytes(self)
    }
}

impl<'a> AsBytes for &'a [u8] {
    fn as_bytes(&self) -> &[u8] {
        *self
    }
}

#[cfg(test)]
mod tests {
    use super::MerkleTree;

    #[test]
    #[should_panic]
    fn test_build_with_0_values() {
        let _t: MerkleTree = MerkleTree::build::<String>(&[]);
    }

    #[test]
    fn test_build_with_odd_number_of_values() {
        let block = "Hello World";
        let _t: MerkleTree = MerkleTree::build(&[block, block, block]);
    }

    #[test]
    fn test_build_with_even_number_of_values() {
        let block = "Hello World";
        let _t: MerkleTree = MerkleTree::build(&[block, block, block, block]);
    }

    #[test]
    fn test_root_hash_stays_the_same_if_data_hasnt_been_changed() {
        let block = "Hello World";
        let t: MerkleTree = MerkleTree::build(&[block, block]);

        assert_eq!("c9978dc3e2d729207ca4c012de993423f19e7bf02161f7f95cdbf28d1b57b88a",
                   t.root_hash_str());
    }

    #[test]
    fn test_root_children_have_the_same_hash_if_blocks_were_the_same() {
        let block = "Hello World";
        let t: MerkleTree = MerkleTree::build(&[block, block, block, block, block]);

        assert_eq!(t.nodes[1].as_slice(), t.nodes[2].as_slice());
    }

    #[test]
    fn test_root_children_have_the_different_hash_if_blocks_were_the_different() {
        let block1 = "Hello World";
        let block2 = "Bye Bye";
        let t: MerkleTree = MerkleTree::build(&[block1, block1, block2, block2]);

        assert_ne!(t.nodes[1].as_slice(), t.nodes[2].as_slice());
    }

    #[test]
    #[should_panic]
    fn test_build_from_leaves_with_0_values() {
        let _t: MerkleTree = MerkleTree::build_from_leaves(&[]);
    }

    #[test]
    fn test_building_a_tree_from_existing_tree() {
        let block = "Hello World";
        let existing_tree: MerkleTree = MerkleTree::build(&[block, block]);

        let new_tree: MerkleTree = MerkleTree::build_from_leaves(existing_tree.leaves());

        assert_eq!(new_tree.root_hash_str(), existing_tree.root_hash_str());
        assert_eq!(new_tree.leaves().len(), existing_tree.leaves().len());
        assert_eq!(new_tree.leaves(), existing_tree.leaves());
    }
}



mod block;
pub use crate::block::Block;

mod hashing;
pub use crate::hashing::Hashing;

mod blockchain;
pub use crate::blockchain::Blockchain;

extern crate crypto;
extern crate rustc_serialize;
extern crate bloom;

mod bench;
mod utils;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::fmt;

use bloom::{ASMS,BloomFilter};

const LEAF_SIG: u8 = 0u8;
const INTERNAL_SIG: u8 = 1u8;

type Hash = Vec<u8>;