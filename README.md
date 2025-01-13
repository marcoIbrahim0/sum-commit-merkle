Sum-Commit-Merkle is a Rust project that implements a Merkle tree structure enhanced with sum-based commitments and exclusive allotment proofs. Designed for applications requiring secure and efficient verification of aggregated numerical data, this library provides a robust framework for building and managing Merkle trees with integrated sum commitments.

🔍 Features
Sum Commitments:

Define and manage commitments based on the sum of numerical values.
Ensure data integrity and verifiability through cryptographic hashes.
Exclusive Allotment Proofs:

Generate proofs that verify the inclusion and correctness of specific values within the Merkle tree.
Support for verifying proofs against a root commitment to ensure data consistency.
Merkle Tree Integration:

Seamlessly create and manage Merkle trees from a vector of values.
Efficiently compute root commitments and generate proofs for any given position within the tree.
Cryptographic Security:

Utilizes the SHA-256 hashing algorithm to ensure the security and immutability of commitments and proofs.
Extensible Traits:

Provides customizable traits (SumCommitment, ExclusiveAllotmentProof, MerkleTree) for flexibility and ease of integration into various projects.

Getting Started
Clone the Repository:

```
 bash
Copy code
git clone https://github.com/marcoIbrahim0/sum-commit-merkle.git
cd sum-commit-merkle
```
Build the Project:
```
bash
Copy code
cargo build
Run the Example:

bash
Copy code
cargo run
```

🚀 Usage Example
Creating a Merkle Tree
```
use sum_commit_merkle::{MyMerkleTree, SumCommitmentStruct, MyExclusiveAllotmentProof};

fn main() {
    let values = vec![10, 20, 30, 40, 50, 60, 70, 80];

    // Create a Merkle tree from a list of values
    let tree: MyMerkleTree<MyExclusiveAllotmentProof<SumCommitmentStruct>> = MyMerkleTree::new(values.clone());
    
    // Compute the root commitment
    let root_commitment = tree.commit();
    println!("Root Commitment: {:?}", root_commitment);
}
```
Generating and Verifying a Proof
rust
Copy code

```
fn main() {
    let values = vec![10, 20, 30, 40, 50, 60, 70, 80];

    // Create a Merkle tree
    let tree: MyMerkleTree<MyExclusiveAllotmentProof<SumCommitmentStruct>> = MyMerkleTree::new(values.clone());
    let root_commitment = tree.commit();

    // Get a proof for a specific position in the tree
    let position_to_prove = 2;
    let proof = tree.prove(position_to_prove);
    println!("Proof for position {}: {:?}", position_to_prove, proof);

    // Verify the proof against the root commitment
    let verified = proof.verify(&root_commitment);
    println!("Proof verified: {}", verified);
}
```
