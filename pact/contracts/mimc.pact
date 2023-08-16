;SPDX-License-Identifier: MIT
(module mimc-v1 GOV
  "Pact implementation of the MiMC hash algorithm \
  \ Github: https://github.com/CryptoPascal31/pact-zk-hashes "

  (defconst VERSION:string "1.0")
  (defcap GOV ()
    (enforce false "Non-upgradable module"))

  (use free.util-lists [append-last last enforce-not-empty])

  ; Load generated constants
  (use mimc-constants-v1 "GkRwic14d-6K6F8dL-PzA1E1erA0pPm3wYWPYNC8zoU")

  ; Modulus to define the field (same as BN128)
  (defconst FIELD-MODULUS:integer 21888242871839275222246405745257275088548364400416034343698204186575808495617)


;;; --------------------------------------------------------------------------
;;; -------------------   UTILITY FUNCTIONS ------------------------------------
  (defun *mod:integer (x:integer y:integer)
    "Compute a modular multiplication"
    (mod (* x y) FIELD-MODULUS))

  (defun +mod:integer (x:integer y:integer)
    "Compute a modular addition"
    (mod (+ x y) FIELD-MODULUS))

  ; This function can be further gas optimized by inlining *mod and +mod
  (defun feistel-round:object (key:integer input:object cst:integer)
    "Compute a round of MiMC"
    (bind input {'L:=l, 'R:=r}
      (let* ((t1 (+ l (+ key cst)))
             (t2 (*mod t1 t1))
             (t4 (*mod t2 t2))
             (t5 (*mod t4 t1)))
        {'L:(+mod r t5), 'R:l}))
  )

  (defun reverse-left-right:object (input:object)
    "Reverse left-right"
    (bind input {'L:=l, 'R:=r}
      {'L:r, 'R:l}))

  (defun hash-absorb:object (key:integer current:object new-data:integer)
    "Absorb a new input data inside the sponge"
    (bind current {'L:=current-x, 'R:=current-y}
      (feistel-hash key {'L:(+ current-x new-data), 'R:current-y})))

  (defun hash-extract:[object] (key:integer current-lst:[object] _:integer)
    "Extract an output data from the sponge"
    (append-last current-lst (feistel-hash key (last current-lst))))


;;; ---------------------------------------------------------------------------
;;; -------------------   PUBLIC CALLABLE FUNCTIONS ----------------------------
  (defun feistel-hash:object (key:integer input:object)
    "Compute the Hash of an MiMC object: {'L:, 'R:}, and returns an MiMC object"
    (reverse-left-right (fold (feistel-round key) input MIMC-CONST)))

  (defun feistel-multi-hash:[integer] (key:integer inputs:[integer] n-outputs:integer)
    "Compute a hash of multiple integers inputs and outputs multiple integers using a sponge structure"
    ; Do some sanity checks
    (enforce-not-empty inputs)
    (enforce (> n-outputs 0) "At least 1 input is required")
    (let* ((initial-state  {'L:0,'R:0})
           (absorb-state (fold (hash-absorb key) initial-state inputs))
           (output-states (if (= n-outputs 1) [absorb-state]
                                              (fold (hash-extract key) [absorb-state] (enumerate 2 n-outputs)))))
      (map (at 'L) output-states))
  )
)
