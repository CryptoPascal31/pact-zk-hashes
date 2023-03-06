# Pact ZK Hashes
This packages contains hash algorithms for use in ZK contracts in Pact, on the Kadena blockchain.

  - MiMC (Sponge contstruction version)
  - Poseidon

---

## MiMC
Pact implementation of the MiMC hash for Kadena.

Compatible with Circom's and ZoKrates's Sponge construction with 220 Rounds:

https://iden3.io/circom

https://github.com/iden3/circomlib/blob/master/circuits/mimcsponge.circom

https://github.com/iden3/circomlibjs/blob/main/src/mimcsponge.js

https://github.com/Zokrates/ZoKrates/tree/develop/zokrates_stdlib/stdlib/hashes/mimcSponge

Constants are generated by keccak256 using the seed `mimcsponge`

### API

```
(defun feistel-hash:object (key:integer input:object)
```
* `key`: key
* `input`: hashing object : {'L:integer 'R:integer}

Returns an hashing object: {'L:integer 'R:integer}

Gas consumption (pact 4.6.0):
  - 27,697

**Equivalence:**

| Library          | Function                                                   |
| ---------------- | -----------------------------------------------------------|
| Circomlib        | MiMCFeistel(220)                                           |
| CircomlibJS      | MIMCSponge.hash()                                          |
| ZoKrates Stdlib  | mimcFeistel(field xL_in, field xR_in, field k) -> field[2] |


---

```
(defun feistel-multi-hash:[integer] (key:integer inputs:[integer] n-outputs:integer)
```

* `key`: key
* `inputs`: input list of integers
* `n-outputs`: Number of outputs integer to return

Returns the hash result as a list of integers.

Gas consumption (pact 4.6.0):
 - 1 input/1 output: 27,724
 - 1 input/10 outputs: 277,160
 - 10 inputs/1 output: 277,189
 - 10 inputs/10 outputs: 526,638

**Equivalence:**

| Library          | Function                                                                      |
| ---------------- | ------------------------------------------------------------------------------|
| Circomlib        | MiMCSponge(nInputs, 220, nOutputs)                                            |
| CircomlibJS      | MIMCSponge.multiHash()                                                        |
| ZoKrates Stdlib  | mimcSponge<nInputs, nOutputs>(field[nInputs] ins, field k) -> field[nOutputs] |

---

---

## POSEIDON
Pact implementation of the Poseidon hash for Kadena:

https://www.poseidon-hash.info/

https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom

https://github.com/iden3/circomlibjs/blob/main/src/poseidon_reference.js

https://github.com/Zokrates/ZoKrates/blob/develop/zokrates_stdlib/stdlib/hashes/poseidon/poseidon.zok

Constants are taken from the Circolib project.

### API

```
(defun poseidon-hash:integer (in:[integer])
```
* `inputs`: input list of integers

Returns the hash result as an integer.

Gas consumption (pact 4.6.0):
 - 1 input/1 output: 20,242
 - 2 inputs/1 output: 36,075
 - 3 inputs/1 output: 56,465
 - 4 inputs/1 output: 88,226
 - 5 inputs/1 output: 122,700


**Equivalence:**

| Library          | Function                                                                      |
| ---------------- | ------------------------------------------------------------------------------|
| Circomlib        | Poseidon(nInputs)                                                             |
| CircomlibJS      | buildPoseidon()(inputs, 0 1)                                                  |
| ZoKrates Stdlib  | poseidon<N>(field[N] inputs) -> field                                         |
