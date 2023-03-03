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
| ZoKrates Stalib  | mimcSponge<nInputs, nOutputs>(field[nInputs] ins, field k) -> field[nOutputs] |
