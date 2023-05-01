use project1::Block;
use project1::Hashing;
use project1::Blockchain;
use project1::BlockHash;
use project1::MerkleTree;
use bloom::{ASMS,BloomFilter};
use project1::AsBytes;
use std::time::{Duration, SystemTime, UNIX_EPOCH};use std::thread::sleep;

fn main() {

    let expected_num_items = 8;///items to be stored in bloom filter
    let false_positive_rate = 0.005;///bloom filter FP rate

    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    println!("{:?}", since_the_epoch);

    let mut hashes: BlockHash = Vec::new();


    let mut transactions = [""; 7];

    transactions[0]= "ebadfaa92f1fd29e2fe296eda702c48bd11ffd52313e986e99ddad9084062167";
    transactions[1]= "6596fd070679de96e405d52b51b8e1d644029108ec4cbfe451454486796a1ecf";
    transactions[2]= "b2affea89ff82557c60d635a2a3137b8f88f12ecec85082f7d0a1f82ee203ac4";
    transactions[3]= "7dbc497969c7475e45d952c4a872e213fb15d45e5cd3473c386a71a1b0c136a1";
    transactions[4]= "55ea01bd7e9afd3d3ab9790199e777d62a0709cf0725e80a7350fdb22d7b8ec6";
    transactions[5]= "12b6a7934c1df821945ee9ee3b3326d07ca7a65fd6416ea44ce8c3db0c078c64";
    transactions[6]= "7f42eda67921ee92eae5f79bd37c68c9cb859b899ce70dba68c48338857b7818";// Dummy Transactions

    let mut filter = BloomFilter::with_rate(false_positive_rate,expected_num_items);///create bloom filter
    for i in 0..7{
            filter.insert(&transactions[i]);
    }// insert all elements in the bloom filter

    
    let t: MerkleTree = MerkleTree::build(&transactions);// built a merkle tree with the transactions
    let leaves_= t.leaves();
    let root_=t.root_hash();// this is root of merkle tree.. also will be the hash of the block

    //println!("{:?}", root_);
    let timestamp: u128 = since_the_epoch.as_millis();

    let mut block = Block::new(13, timestamp, vec![0; 32], root_.to_vec(), "Genesis block!". to_owned (), 0);// create new block
    println!("{:?}", &block);

    let mut last_hash = block.hash.clone();//used if using multiple blocks

    let search_transaction ="7dbc497969c7475e45d952c4a872e213fb15d45e5cd3473c386a71a1b0c136a1";//transaction we'll be searching

    if filter.contains(&search_transaction)==true//check if transaction present in the bloom filter
    {

        println!("Exists in Bloom Filter\n Checking the transaction in MerkleTree:");
        let mut present: bool= false;
        for i in 0..7
        {   
            if transactions[i]==search_transaction//check if transaction present in the leaf nodes of the tree
            {
                present=true;
            }
        }
            if present
            {
                let tt: MerkleTree = MerkleTree::build_from_leaves(&leaves_);//reconstruct the tree using the leaf nodes
                if(root_==tt.root_hash())//see if the original root hash and new tree hash node match
                {
                    println!("Transaction exists in the tree");
                }
            }
            else {
                    println!("False Positive in bloom filter. Transaction not present.")   
            }
    }

}
