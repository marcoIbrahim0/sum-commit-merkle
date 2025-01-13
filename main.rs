extern crate sha2;
use sha2::{Digest, Sha256};

// Define the SumCommitment trait with two required methods: amount and digest
pub trait SumCommitment {
    fn amount(&self) -> u64;
    fn digest(&self) -> [u8; 32];
}

// Define the ExclusiveAllotmentProof trait, which depends on a type C implementing SumCommitment
pub trait ExclusiveAllotmentProof<C: SumCommitment> {
    fn position(&self) -> usize; // Method to get the position of the proof
    fn sibling(&self, height: u8) -> Option<C>; // Method to get a sibling commitment at a given height
    fn verify(&self, root_commitment: &C) -> bool; // Method to verify the proof against a root commitment
}

// Define the MerkleTree trait, which depends on types C and P implementing SumCommitment and ExclusiveAllotmentProof respectively
pub trait MerkleTree<C: SumCommitment, P: ExclusiveAllotmentProof<C>> {
    fn new(values: Vec<u64>) -> Self; // Method to create a new Merkle tree from a vector of u64 values
    fn commit(&self) -> C; // Method to get the root commitment of the tree
    fn prove(&self, position: usize) -> &P; // Method to get a proof for a given position
}

fn hash_bytes(slice: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(slice);
    hasher.finalize().into()
}

// Function to concatenate two 32-byte hashes into a single 64-byte hash

fn concatenate_hashes(hash1: &[u8; 32], hash2: &[u8; 32]) -> [u8; 64] {
    let mut result = [0; 64];
    result[..32].copy_from_slice(hash1);
    result[32..].copy_from_slice(hash2);
    result
}
// SumCommitmentStruct implementation
#[derive(Clone, Debug)]
pub struct SumCommitmentStruct {
    amount: u64,
    digest: [u8; 32],
}

impl SumCommitment for SumCommitmentStruct {
    fn amount(&self) -> u64 {
        self.amount
    }
    fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

// MyExclusiveAllotmentProof implementation
#[derive(Debug)]
pub struct MyExclusiveAllotmentProof<C: SumCommitment> {
    position: usize,
    commitments: Vec<C>,
}

impl<C: SumCommitment + Clone> Clone for MyExclusiveAllotmentProof<C> {
    fn clone(&self) -> Self {
        Self {
            position: self.position,
            commitments: self.commitments.clone(),
        }
    }
}

impl<C: SumCommitment + Clone> ExclusiveAllotmentProof<C> for MyExclusiveAllotmentProof<C> {
    fn position(&self) -> usize {
        self.position
    }

    fn sibling(&self, height: u8) -> Option<C> {
        if height == 0 {
            return None;
        }

        let parent_position = self.position() / 2;
        // Determine if the current node is a left child or a right child
        let is_left_child = self.position() % 2 == 0;
        let sibling_position = if is_left_child { parent_position * 2 + 1 } else { parent_position * 2 };

        // Attempt to retrieve the sibling commitment from the commitments vector
        if let Some(sibling_commitment) = self.commitments.get(sibling_position) {
            // If found, clone the commitment and return it as Some
            Some(sibling_commitment.clone())
        } else {
            None
        }
    }

    // Verify the proof against the provided root commitment
    fn verify(&self, root_commitment: &C) -> bool {
        // Get the commitment associated with the proof's position
        let self_commitment = match self.commitments.get(self.position()) {
            Some(commitment) => commitment,  // If found, store the commitment
            None => return false,
        };
        // Compute the hash of the self commitment's digest
        let self_commitment_hash = hash_bytes(&self_commitment.digest());
        // Compare the computed hash with the root commitment's digest
        &self_commitment_hash[..] == &root_commitment.digest()[..]
    }
}

// MyMerkleTree implementation
pub struct MyMerkleTree<P: ExclusiveAllotmentProof<SumCommitmentStruct>> {
    proofs: Vec<P>,
    commitments: Vec<SumCommitmentStruct>,
    root_commitment: Option<SumCommitmentStruct>,
}

impl<P: ExclusiveAllotmentProof<SumCommitmentStruct>> MyMerkleTree<P> {

    // Calculate the sum of values and validate it
    // Create commitments and set the root commitment
    fn new(values: Vec<u64>) -> Self {
        // Calculate the sum of the provided values

        let sum: u64 = values.iter().sum();
        // Check if the sum exceeds a specified threshold
        if sum > 1_000_000_000 {
            panic!("Sum of values exceeds 1,000,000,000");
        }
        // Create commitments by iterating over the values and mapping them to SumCommitmentStructs
        let commitments: Vec<SumCommitmentStruct> = values.iter()
            .map(|&value| {
                SumCommitmentStruct {
                    amount: value,
                    digest: hash_bytes(&value.to_be_bytes()),
                }
            })
            .collect();
        // Extract and clone the root commitment from the commitments vector
        let root_commitment = commitments.last().unwrap().clone();
        // Create a new instance of MyMerkleTree with initialized fields
        Self {
            commitments, // Store the commitments in the tree
            proofs: Vec::new(), // Initialize an empty vector to store proofs
            root_commitment: Some(root_commitment), // Store the root commitment here
        }
    }


    fn commit(&self) -> SumCommitmentStruct {
        // Create a vector of leaf hashes by extracting the digests of the commitments

        let mut leaf_hashes: Vec<[u8; 32]> = self.commitments.iter().map(|c| c.digest()).collect();
        // Continue until there is only one hash left (the root commitment)

        while leaf_hashes.len() > 1 {
            // Create a vector to store the parent hashes
            let mut parent_hashes = Vec::new();
            // Process leaf hashes in pairs (chunks of 2)
            for chunk in leaf_hashes.chunks(2) {
                let mut hasher = Sha256::new();
                let mut combined = Vec::new();
                // Concatenate and extend the hashes of the two child nodes
                combined.extend_from_slice(&concatenate_hashes(&chunk[0], &chunk[1]));
                // Update the hasher with the combined hashes
                hasher.update(&combined);
                // Push the resulting hash into the parent hashes vector
                parent_hashes.push(hasher.finalize().into());
            }
    
            if leaf_hashes.len() % 2 == 1 {
                parent_hashes.push(*leaf_hashes.last().unwrap());
            }
    
            leaf_hashes = parent_hashes;
        }
        // Return the final root commitment
        SumCommitmentStruct {
            amount: 0, // Placeholder value, as it's not used in the Merkle tree
            digest: leaf_hashes[0],
        }
    }
    // Return the proof for the given position
    fn prove(&self, position: usize) -> &P {
        &self.proofs[position]
    }
}

fn main() {
    let values = vec![10, 20, 30, 40, 50, 60, 70, 80];
    let tree: MyMerkleTree<MyExclusiveAllotmentProof<SumCommitmentStruct>> = MyMerkleTree::new(values.clone());
    let root_commitment = tree.commit();

    println!("Root Commitment: {:?}", root_commitment);

    let position_to_prove = 2;
    let proof = tree.prove(position_to_prove);
    println!("Proof for position {}: {:?}", position_to_prove, proof);

    let verified = proof.verify(&root_commitment);
    println!("Proof verified: {}", verified);
}
