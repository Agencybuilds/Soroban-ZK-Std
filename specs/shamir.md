# Z-Loroban: Fiat-Shamir Transcript Rules


This document outlines the transcript construction rules for the Fiat-Shamir heuristic within the ZK-Soroban framework, ensuring non-interactive proof security.

## 1. Transcript Initialization
The transcript must be initialized with the system's public parameters to bind the proof to the specific circuit and configuration.
- **Components:** `[DomainSeparator || CircuitID || PublicParameters]`

## 2. Interactive-to-Non-Interactive Conversion
To achieve the non-interactive property, every challenge $c$ must be derived from the hash of all preceding transcript elements.

### Rule: Sequential Commitment
1.  **Commitment Phase:** Generate a commitment $A$ (e.g., Pederson commitment).
2.  **Challenge Generation:** Compute $c = \text{Hash}(\text{Transcript} || A)$.
3.  **Update Transcript:** Append $A$ and $c$ to the transcript.
    - `Transcript_{new} = Transcript_{old} || A || c`

## 3. Transcript Integrity Requirements
- **Domain Separation:** Every distinct proof step must use a unique domain separator prefix to prevent cross-protocol replay attacks.
- **Fixed-Length Encoding:** All transcript elements must be encoded using a canonical, fixed-length byte representation (e.g., Big-Endian serialization).
- **Binding Property:** The transcript must include the entire set of public inputs/outputs associated with the statement being proven.

## 4. Security Constraints
- **Collision Resistance:** The hash function used must be cryptographically collision-resistant (e.g., SHA-256 or Poseidon for ZK-friendly circuits).
- **No External State:** The challenge derivation must strictly depend on the provided transcript elements. Do not include volatile external state (e.g., timestamps) in the hash input.

## 5. State Machine Definition
The Fiat-Shamir transcript is implemented as a deterministic state machine with the following states and transitions:

### States
- **Initialized:** The transcript has been created with the domain separator, circuit ID, and public parameters.
- **Absorbing:** The transcript is accepting a new commitment or public input to be appended.
- **Squeezing:** The transcript is ready to derive a challenge from the current state.
- **Finalized:** All challenges have been derived and the transcript is closed.

### Transitions
1.  **Initialize -> Absorbing:** Append the domain separator, circuit ID, and public parameters.
2.  **Absorbing -> Absorbing:** Append a commitment or public input with its domain separator.
3.  **Absorbing -> Squezing:** The transcript is ready to derive a challenge.
4.  **Squeezing -> Absorbing:** Derive a challenge from the current transcript state and append it back to the transcript.
5.  **Squeezing -> Finalized:** Mark the transcript as closed after all challenges have been derived.

### Challenge Derivation Sequence
The PLONK verifier derives the four challenges $q\alpha, \beta, \gamma, \zeta$ in a fixed order, each bound to the transcript state at the time of derivation:

1.  **$\alpha$:** Derived after absorbing the wire commitments $[a], [b], [c]$ and the public inputs $[x]`, $[x]$.
2.  **\beta$:** Derived after absorbing the permutation grandhometry commitments $[z]$ and $[s_\sigma]$.
3.  **\gamma$:** Derived after absorbing the quotient commitments $[t], $[r]$ and the linearization commitment $[w]$ and $[w_zeta]$.
4.  **$zeta$:** Derived after absorbing the opening evaluations and the final proof elements.

Each challenge is computed as $x = \text{Hash}(\text{DomainSeparator} || \text{Transcript})$ and then appended to the transcript before the next commitment is absorbed.

## 6. Implementation Notes
- The transcript must be implemented as an append-only buffer of canonically encoded bytes.
- All hash inputs use the full transcript buffer concatenated with the new element.
- The challenge derivation must be deterministic given the transcript buffer and must not depend on any external state.
- The domain separator for each challenge must be unique and fixed by the protocol specification.
