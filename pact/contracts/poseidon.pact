;SPDX-License-Identifier: MIT
(module poseidon-hash-v1 GOV
  "Pact implementation of the Poseidon hash algorithm \
  \ Github: https://github.com/CryptoPascal31/pact-zk-hashes "
  (defconst VERSION "1.0")
  (defcap GOV() false)

  (use free.util-lists [first replace-first])

  (use poseidon-constants-v1)

  ; Modulus to define the field (same as BN128)
  (defconst FIELD-MODULUS:integer 21888242871839275222246405745257275088548364400416034343698204186575808495617)

  ;;; --------------------------------------------------------------------------
  ;;; --------------------MODULAR ARITHMETIC FUNCTIONS -------------------------
  (defun --mod:integer (x:integer)
    "Apply the field modulus on an integer"
    (mod x FIELD-MODULUS))

  (defun *mod:integer (x:integer y:integer)
    "Compute a modular multiplication"
    (mod (* x y) FIELD-MODULUS))


  ;;; -------------------------------------------------------------------------
  ;;; -------------------- VECTOR / MATRIX FUNCTIONS --------------------------
  (defun +vec:[integer] (v1:[integer] v2:[integer])
    "Compute the sum of 2 vectors"
    (zip (+) v1 v2))

  (defun *vec:integer (v1:[integer] v2:[integer])
    "Dot products of 2 vectors"
    (fold (+) 0 (zip (*mod) v1 v2)))

  (defun *mat:[integer] (mat:[[integer]] vector:[integer])
    "Multiply a vector by a square matrix"
    (map (*vec vector) mat))


  ;;; --------------------------------------------------------------------------
  ;;; -------------------------- S-BOX LAYER -----------------------------------
  (defun s-box:integer (x:integer)
    "S box function: modular x => x^5 "
    (let* ((x2 (*mod x x))
           (x4 (*mod x2 x2)))
      (*mod x4 x))
  )

  (defun s-box-layer-full:[integer] (in:[integer])
    "S-Box layer of a full round: apply s-box on each element"
    (map (s-box) in))

  (defun s-box-layer-partial:[integer] (in:[integer])
    "S-Box layer of a partial round: apply s-box on the first element only"
    (replace-first in (s-box (first in))))


  ;;; --------------------------------------------------------------------------
  ;;; -----------------------POSEIDON ROUNDS -----------------------------------
  (defun full-round:[integer] (mix-matrix:[[integer]] in:[integer] arc-constants:[integer])
    "Compute a Poseidon full round"
    (compose   (+vec arc-constants)
      (compose (s-box-layer-full)
               (*mat mix-matrix))
      in)
  )

  (defun partial-round:[integer] (mix-matrix:[[integer]] in:[integer] arc-constants:[integer])
    "Compute a Poseidon partial round (with a partial S+-Box layer)"
    (compose   (+vec arc-constants)
      (compose (s-box-layer-partial)
               (*mat  mix-matrix))
      in)
  )

  (defun poseidon-rounds:[integer] (state:[integer] params:object)
    ""
    (bind params {'MATRIX:=matrix, 'ARC-CONST:=consts}
      (let* (
             ;4 Full rounds
             (state (fold (full-round matrix) state (take 4 consts)))
             ; N -8 partial rounds
             (state (fold (partial-round matrix) state (drop 4 (drop -4 consts))))
             ; 4 Full rounds
             (state (fold (full-round matrix) state (take -4 consts))))
        ; Apply modulo on the final state
        (map (--mod) state)))
  )

  ;;; --------------------------------------------------------------------------
  ;;; -------------------- PUBLIC FUNCTION - -----------------------------------
  (defun poseidon-hash:integer (inputs:[integer])
    (let* ((initial-state (+ [0] inputs))
           (params (cond
                     ((= (length inputs) 1) CST-T2)
                     ((= (length inputs) 2) CST-T3)
                     ((= (length inputs) 3) CST-T4)
                     ((= (length inputs) 4) CST-T5)
                     ((= (length inputs) 5) CST-T6)
                     [(enforce false "Unsupported input length")]))
           (final-state (poseidon-rounds initial-state params)))
      (at 0 final-state))
  )
)
