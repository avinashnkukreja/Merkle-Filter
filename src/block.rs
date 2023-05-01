use std::collections::hash_map::DefaultHasher;
/*use std::hash::{Hash, Hasher};*/
use std::fmt:: {self, Debug, Formatter };
use super::*;

pub struct Block {
	pub index: u32, 
	pub timestamp: u128,
	pub prev_block_hash: BlockHash ,
	pub hash: BlockHash,
	pub nonce: u64,
	pub payload: String,
}



impl Debug for Block {
	fn fmt (&self, f: &mut Formatter) -> fmt:: Result
	{
		write!(f, "Block[{}]: {} at: {} with: {}", 
			&self.index,
			&hex:: encode(&self.hash), 
			&self.timestamp,
			&self.payload,
			)
	}
}

impl Block {
	pub fn new (index: u32, timestamp: u128, prev_block_hash: BlockHash, hash: BlockHash, payload: String, nonce: u64) -> Self
	{
		return Block {
			index,
			timestamp,
			prev_block_hash,
			hash,
			payload,
			nonce
		};
	}
}
