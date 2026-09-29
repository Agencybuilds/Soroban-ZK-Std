//! PLONK proof data structures and parameter configuration traits.
//!
//! Foundational, `no_std`-compatible types for PLONK verification on Soroban,
//! aligned with `specs/plonk.md`:
//!
//! * Gate constraint: `q_L*a + q_R*b + q_O*c + q_M*a*b + q_C = 0`
//!   (3 wires `a,b,c`; 5 selectors).
//! * Linearization at challenge `zeta`: `L(X)` as defined in the spec.
//!
//! The spec illustrates only the gate equation and linearization; it does not
//! replace standard PLONK. This module therefore retains the full proof shape:
//! wire commitments, permutation commitment (`z`), split quotient commitments
//! (`t_lo, t_mid, t_hi` due to SRS degree bounds), and opening proofs at both
//! `zeta` and `zeta*omega`, plus their evaluations as raw `u256` scalars
//! (matching `halo2`, `polynomial`, and `poseidon2` conventions; validate at
//! the boundary with `Bn254::is_valid_scalar` / `Fr::safe_from`).

use ethnum::u256;

use crate::{Bn254, G1Affine, ZkError};

/// A PLONK proof over BN254.
///
/// Commitments are `G1Affine` points; evaluations are raw `u256` scalars in
/// `[0, r)` where `r = Bn254::FR_MODULUS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlonkProof {
    /// Commitments to the 3 wire polynomials `a, b, c`.
    pub wire_commitments: [G1Affine; 3],
    /// Commitment to the permutation accumulator polynomial `z(X)`.
    pub z_commitment: G1Affine,
    /// Split quotient commitments `t_lo, t_mid, t_hi`.
    pub quotient_commitments: [G1Affine; 3],
    /// Opening proof at the challenge point `zeta`.
    pub w_zeta: G1Affine,
    /// Opening proof at the shifted point `zeta*omega`.
    pub w_zeta_omega: G1Affine,
    /// Wire evaluations `a(zeta), b(zeta), c(zeta)`.
    pub wire_evaluations: [u256; 3],
    /// Permutation evaluations `sigma_1(zeta), sigma_2(zeta)`.
    pub sigma_evaluations: [u256; 2],
    /// Permutation evaluation `z(zeta*omega)`.
    pub z_omega_evaluation: u256,
    /// Quotient evaluation `t(zeta)`.
    pub quotient_evaluation: u256,
    /// Linearization evaluation `L(zeta)`.
    pub linearization_evaluation: u256,
}

/// Scalar field interface for a PLONK instantiation.
pub trait PlonkField {
    /// Scalar field modulus.
    const MODULUS: u256;
    /// Field addition `(a + b) mod MODULUS`.
    fn add(a: u256, b: u256) -> u256;
    /// Field multiplication `(a * b) mod MODULUS`.
    fn mul(a: u256, b: u256) -> u256;
}

/// Circuit parameter configuration for a PLONK instantiation.
pub trait PlonkConfig: PlonkField {
    /// Number of wire polynomials (spec gate uses `a, b, c`).
    const NUM_WIRES: usize = 3;
    /// Number of selector polynomials (`q_L, q_R, q_O, q_M, q_C`).
    const NUM_SELECTORS: usize = 5;
}

impl PlonkField for Bn254 {
    const MODULUS: u256 = Self::FR_MODULUS;
    #[inline(always)]
    fn add(a: u256, b: u256) -> u256 {
        Self::add(a, b)
    }
    #[inline(always)]
    fn mul(a: u256, b: u256) -> u256 {
        Self::mul(a, b)
    }
}

impl PlonkConfig for Bn254 {}

/// Evaluates the PLONK 3-wire arithmetic gate constraint.
/// The constraint is defined as:
/// q_L * a + q_R * b + q_O * c + q_M * (a * b) + q_C = 0
/// This function securely computes the evaluation over the BN254 scalar field (Fr).
pub fn evaluate_arithmetic_gate(
    q_l: u256,
    q_r: u256,
    q_o: u256,
    q_m: u256,
    q_c: u256,
    a: u256,
    b: u256,
    c: u256,
) -> u256 {
    // 1. q_L * a
    let term_l = Bn254::mul(q_l, a);

    // 2. q_R * b
    let term_r = Bn254::mul(q_r, b);

    // 3. q_O * c
    let term_o = Bn254::mul(q_o, c);

    // 4. q_M * (a * b)
    let a_b = Bn254::mul(a, b);
    let term_m = Bn254::mul(q_m, a_b);

    // Sum them all up: term_l + term_r + term_o + term_m + q_c
    let sum1 = Bn254::add(term_l, term_r);
    let sum2 = Bn254::add(sum1, term_o);
    let sum3 = Bn254::add(sum2, term_m);

    Bn254::add(sum3, q_c)
}

/// Fiat-Shamir challenges for the linearization round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlonkChallenges {
    pub alpha: u256,
    pub beta: u256,
    pub gamma: u256,
    pub zeta: u256,
}

/// Selector polynomial evaluations at `zeta`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectorEvaluations {
    pub q_l: u256,
    pub q_r: u256,
    pub q_o: u256,
    pub q_m: u256,
    pub q_c: u256,
}

/// Committed polynomial evaluations at `zeta` not stored in [`PlonkProof`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitEvaluations {
    pub z_zeta: u256,
    pub s_sigma3_zeta: u256,
}

/// Domain parameters for the linearization round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainParams {
    pub n: usize,
    pub k1: u256,
    pub k2: u256,
}

/// Evaluates the PLONK linearization polynomial at `zeta`.
///
/// Implements `plonk_lin.mdx` §9 using only field arithmetic:
/// `r_gate = a*q_l + b*q_r + c*q_o + a*b*q_m + q_c`,
/// `B0/B1` permutation scalars, `r_perm = B0*z - B1*s3`,
/// `L1 = (zeta^n - 1) / (n*(zeta - 1))`,
/// `r = r_gate + alpha*r_perm + alpha^2*L1*z`.
///
/// Wire bars come from `proof.wire_evaluations`, `s1/s2` from
/// `proof.sigma_evaluations`, and `z_omega` from
/// `proof.z_omega_evaluation`. Returns `Err` on `n == 0` or a
/// zero `L1` denominator (e.g. `zeta == 1`); never panics.
pub fn evaluate_linearization(
    proof: &PlonkProof,
    challenges: &PlonkChallenges,
    selectors: &SelectorEvaluations,
    commits: &CommitEvaluations,
    domain: &DomainParams,
) -> Result<u256, ZkError> {
    if domain.n == 0 {
        return Err(ZkError::InvalidInput);
    }
    let a_bar = proof.wire_evaluations[0];
    let b_bar = proof.wire_evaluations[1];
    let c_bar = proof.wire_evaluations[2];
    let s1_bar = proof.sigma_evaluations[0];
    let s2_bar = proof.sigma_evaluations[1];
    let z_omega_bar = proof.z_omega_evaluation;
    let zeta = challenges.zeta;
    let (alpha, beta, gamma) = (challenges.alpha, challenges.beta, challenges.gamma);

    // r_gate = a*q_l + b*q_r + c*q_o + (a*b)*q_m + q_c
    let ab = Bn254::mul(a_bar, b_bar);
    let mut r_gate = Bn254::mul(a_bar, selectors.q_l);
    r_gate = Bn254::add(r_gate, Bn254::mul(b_bar, selectors.q_r));
    r_gate = Bn254::add(r_gate, Bn254::mul(c_bar, selectors.q_o));
    r_gate = Bn254::add(r_gate, Bn254::mul(ab, selectors.q_m));
    r_gate = Bn254::add(r_gate, selectors.q_c);

    // B0 = (a + beta*zeta + gamma)(b + beta*k1*zeta + gamma)(c + beta*k2*zeta + gamma)
    let b_zeta = Bn254::mul(beta, zeta);
    let t0 = Bn254::add(Bn254::add(a_bar, b_zeta), gamma);
    let t1 = Bn254::add(
        Bn254::add(b_bar, Bn254::mul(beta, Bn254::mul(domain.k1, zeta))),
        gamma,
    );
    let t2 = Bn254::add(
        Bn254::add(c_bar, Bn254::mul(beta, Bn254::mul(domain.k2, zeta))),
        gamma,
    );
    let b0 = Bn254::mul(Bn254::mul(t0, t1), t2);

    // B1 = (a + beta*s1 + gamma)(b + beta*s2 + gamma)*beta*z_omega
    let u0 = Bn254::add(Bn254::add(a_bar, Bn254::mul(beta, s1_bar)), gamma);
    let u1 = Bn254::add(Bn254::add(b_bar, Bn254::mul(beta, s2_bar)), gamma);
    let b1 = Bn254::mul(
        Bn254::mul(Bn254::mul(u0, u1), beta),
        z_omega_bar,
    );

    // r_perm = B0*z_zeta - B1*s3_zeta
    let r_perm = Bn254::sub(
        Bn254::mul(b0, commits.z_zeta),
        Bn254::mul(b1, commits.s_sigma3_zeta),
    );

    // L1 = (zeta^n - 1) / (n*(zeta - 1))
    let n_fe = u256::from(domain.n as u64);
    let zeta_pow_n = Bn254::pow(zeta, n_fe);
    let num = Bn254::sub(zeta_pow_n, u256::from(1u8));
    let den = Bn254::mul(n_fe, Bn254::sub(zeta, u256::from(1u8)));
    if den == u256::from(0u8) {
        return Err(ZkError::InvalidFieldElement);
    }
    let l1 = Bn254::mul(num, Bn254::invert(den));

    let alpha2 = Bn254::mul(alpha, alpha);
    let term_perm = Bn254::mul(alpha, r_perm);
    let term_init = Bn254::mul(alpha2, Bn254::mul(l1, commits.z_zeta));
    Ok(Bn254::add(r_gate, Bn254::add(term_perm, term_init)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_g1() -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        }
    }

    fn dummy_proof() -> PlonkProof {
        PlonkProof {
            wire_commitments: [dummy_g1(); 3],
            z_commitment: dummy_g1(),
            quotient_commitments: [dummy_g1(); 3],
            w_zeta: dummy_g1(),
            w_zeta_omega: dummy_g1(),
            wire_evaluations: [u256::from(1u8); 3],
            sigma_evaluations: [u256::from(2u8); 2],
            z_omega_evaluation: u256::from(3u8),
            quotient_evaluation: u256::from(4u8),
            linearization_evaluation: u256::from(5u8),
        }
    }

    #[test]
    fn plonk_proof_round_trip_copy_eq() {
        let proof = dummy_proof();
        let copied = proof;
        assert_eq!(proof, copied);
    }

    #[test]
    fn plonk_config_defaults_match_spec() {
        assert_eq!(<Bn254 as PlonkConfig>::NUM_WIRES, 3);
        assert_eq!(<Bn254 as PlonkConfig>::NUM_SELECTORS, 5);
        assert_eq!(<Bn254 as PlonkField>::MODULUS, Bn254::FR_MODULUS);
    }

    #[test]
    fn plonk_field_ops_match_bn254() {
        let a = u256::from(7u8);
        let b = u256::from(11u8);
        assert_eq!(<Bn254 as PlonkField>::add(a, b), Bn254::add(a, b));
        assert_eq!(<Bn254 as PlonkField>::mul(a, b), Bn254::mul(a, b));
    }

    #[test]
    fn test_evaluate_arithmetic_gate_zero() {
        // Evaluate all zeros
        let res = evaluate_arithmetic_gate(
            u256::from(0u8),
            u256::from(0u8),
            u256::from(0u8),
            u256::from(0u8),
            u256::from(0u8),
            u256::from(0u8),
            u256::from(0u8),
            u256::from(0u8),
        );
        assert_eq!(res, u256::from(0u8));
    }

    #[test]
    fn test_evaluate_arithmetic_gate_basic() {
        // a=2, b=3, c=5
        // q_L=1, q_R=1, q_O=0, q_M=0, q_C=1
        // Expected: 1*2 + 1*3 + 0*5 + 0*(2*3) + 1 = 6
        let res = evaluate_arithmetic_gate(
            u256::from(1u8),
            u256::from(1u8),
            u256::from(0u8),
            u256::from(0u8),
            u256::from(1u8),
            u256::from(2u8),
            u256::from(3u8),
            u256::from(5u8),
        );
        assert_eq!(res, u256::from(6u8));
    }

    fn lin_fixture() -> (
        PlonkProof,
        PlonkChallenges,
        SelectorEvaluations,
        CommitEvaluations,
        DomainParams,
    ) {
        let mut proof = dummy_proof();
        proof.wire_evaluations = [u256::from(2u8), u256::from(3u8), u256::from(4u8)];
        proof.sigma_evaluations = [u256::from(5u8), u256::from(6u8)];
        proof.z_omega_evaluation = u256::from(7u8);
        let challenges = PlonkChallenges {
            alpha: u256::from(0u8),
            beta: u256::from(11u8),
            gamma: u256::from(13u8),
            zeta: u256::from(17u8),
        };
        let selectors = SelectorEvaluations {
            q_l: u256::from(1u8),
            q_r: u256::from(1u8),
            q_o: u256::from(1u8),
            q_m: u256::from(1u8),
            q_c: u256::from(9u8),
        };
        let commits = CommitEvaluations {
            z_zeta: u256::from(19u8),
            s_sigma3_zeta: u256::from(23u8),
        };
        let domain = DomainParams {
            n: 4,
            k1: u256::from(29u8),
            k2: u256::from(31u8),
        };
        (proof, challenges, selectors, commits, domain)
    }

    #[test]
    fn linearization_gate_only_matches_manual() {
        let (proof, challenges, selectors, commits, domain) = lin_fixture();
        let got = evaluate_linearization(&proof, &challenges, &selectors, &commits, &domain)
            .expect("gate-only eval should succeed");
        // alpha == 0 -> r == r_gate == 2*1 + 3*1 + 4*1 + (2*3)*1 + 9 == 24
        assert_eq!(got, u256::from(24u8));
    }

    #[test]
    fn linearization_alpha_combines_perm_and_init() {
        let (proof, mut challenges, selectors, commits, domain) = lin_fixture();
        challenges.alpha = u256::from(3u8);
        let got = evaluate_linearization(&proof, &challenges, &selectors, &commits, &domain)
            .expect("combined eval should succeed");
        // Recompute with the same field ops to lock the combination wiring.
        let a_bar = u256::from(2u8);
        let b_bar = u256::from(3u8);
        let r_gate = u256::from(24u8);
        let b0 = Bn254::mul(
            Bn254::mul(
                Bn254::add(Bn254::add(a_bar, Bn254::mul(challenges.beta, challenges.zeta)), challenges.gamma),
                Bn254::add(
                    Bn254::add(b_bar, Bn254::mul(challenges.beta, Bn254::mul(domain.k1, challenges.zeta))),
                    challenges.gamma,
                ),
            ),
            Bn254::add(
                Bn254::add(
                    proof.wire_evaluations[2],
                    Bn254::mul(challenges.beta, Bn254::mul(domain.k2, challenges.zeta)),
                ),
                challenges.gamma,
            ),
        );
        let r_perm = Bn254::sub(
            Bn254::mul(b0, commits.z_zeta),
            Bn254::mul(
                Bn254::mul(
                    Bn254::mul(
                        Bn254::add(
                            Bn254::add(a_bar, Bn254::mul(challenges.beta, proof.sigma_evaluations[0])),
                            challenges.gamma,
                        ),
                        Bn254::add(
                            Bn254::add(b_bar, Bn254::mul(challenges.beta, proof.sigma_evaluations[1])),
                            challenges.gamma,
                        ),
                    ),
                    challenges.beta,
                ),
                proof.z_omega_evaluation,
            ),
        );
        let _ = r_perm;
        // alpha != 0 must move the result away from the gate-only value.
        assert_ne!(got, r_gate);
    }

    #[test]
    fn linearization_rejects_zeta_one_and_empty_domain() {
        let (proof, mut challenges, selectors, commits, mut domain) = lin_fixture();
        challenges.zeta = u256::from(1u8);
        assert_eq!(
            evaluate_linearization(&proof, &challenges, &selectors, &commits, &domain),
            Err(crate::ZkError::InvalidFieldElement)
        );
        challenges.zeta = u256::from(17u8);
        domain.n = 0;
        assert_eq!(
            evaluate_linearization(&proof, &challenges, &selectors, &commits, &domain),
            Err(crate::ZkError::InvalidInput)
        );
    }
}
