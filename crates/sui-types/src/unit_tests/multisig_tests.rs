// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    base_types::SuiAddress,
    crypto::{get_key_pair, Signature, SuiKeyPair},
    intent::{Intent, IntentMessage, PersonalMessage},
    multisig::AuthenticatorTrait,
};

use super::{MultiPublicKey, MultiSignature};

#[test]
fn multisig_scenarios() {
    let ed_kp: SuiKeyPair = SuiKeyPair::Ed25519(get_key_pair().1);
    let k1_kp: SuiKeyPair = SuiKeyPair::Secp256k1(get_key_pair().1);
    let r1_kp: SuiKeyPair = SuiKeyPair::Secp256r1(get_key_pair().1);

    let pk1 = ed_kp.public();
    let pk2 = k1_kp.public();
    let pk3 = r1_kp.public();

    let multi_pk = MultiPublicKey::new(
        vec![pk1.clone(), pk2.clone(), pk3.clone()],
        vec![1, 1, 1],
        2,
    )
    .unwrap();
    let addr = SuiAddress::from(multi_pk.clone());
    let msg = IntentMessage::new(
        Intent::default(),
        PersonalMessage {
            message: "Hello".as_bytes().to_vec(),
        },
    );
    let sig1 = Signature::new_secure(&msg, &ed_kp);
    let sig2 = Signature::new_secure(&msg, &k1_kp);
    let sig3 = Signature::new_secure(&msg, &r1_kp);

    // Any 2 of 3 signatures verifies ok.
    let multisig1 =
        MultiSignature::combine(vec![sig1.clone(), sig2.clone()], multi_pk.clone()).unwrap();
    assert!(multisig1.verify_secure_generic(&msg, addr).is_ok());

    let multisig2 =
        MultiSignature::combine(vec![sig1.clone(), sig3.clone()], multi_pk.clone()).unwrap();
    assert!(multisig2.verify_secure_generic(&msg, addr).is_ok());

    let multisig3 =
        MultiSignature::combine(vec![sig2.clone(), sig3.clone()], multi_pk.clone()).unwrap();
    assert!(multisig3.verify_secure_generic(&msg, addr).is_ok());

    // 1 of 3 signature verify fails.
    let multisig4 = MultiSignature::combine(vec![sig2.clone()], multi_pk).unwrap();
    assert!(multisig4.verify_secure_generic(&msg, addr).is_err());

    // Incorrect address fails.
    let kp4: SuiKeyPair = SuiKeyPair::Secp256r1(get_key_pair().1);
    let pk4 = kp4.public();
    let multi_pk_1 = MultiPublicKey::new(
        vec![pk1.clone(), pk2.clone(), pk3.clone(), pk4],
        vec![1, 1, 1, 1],
        1,
    )
    .unwrap();
    let multisig5 = MultiSignature::combine(vec![sig1.clone(), sig2.clone()], multi_pk_1).unwrap();
    assert!(multisig5.verify_secure_generic(&msg, addr).is_err());

    // Weight of pk1: 1, pk2: 2, pk3: 3, threshold 3.
    let multi_pk_2 = MultiPublicKey::new(vec![pk1, pk2, pk3], vec![1, 2, 3], 3).unwrap();
    let addr_2 = SuiAddress::from(multi_pk_2.clone());

    // sig1 and sig2 (3 of 6) verifies ok.
    let multi_sig_6 =
        MultiSignature::combine(vec![sig1, sig2.clone()], multi_pk_2.clone()).unwrap();
    assert!(multi_sig_6.verify_secure_generic(&msg, addr_2).is_ok());

    // sig3 (3 of 6) itself verifies ok.
    let multi_sig_7 = MultiSignature::combine(vec![sig3], multi_pk_2.clone()).unwrap();
    assert!(multi_sig_7.verify_secure_generic(&msg, addr_2).is_ok());

    // sig2 (2 of 6)itself verifies fail.
    let multi_sig_8 = MultiSignature::combine(vec![sig2], multi_pk_2).unwrap();
    assert!(multi_sig_8.verify_secure_generic(&msg, addr_2).is_err());
}

#[test]
fn test_serde() {
    // multi_pk

    // multi_sig

    // pubkey

    // compressed sig
}

#[test]
fn single_sig_port_works() {
    let kp: SuiKeyPair = SuiKeyPair::Ed25519(get_key_pair().1);
    let addr = SuiAddress::from(&kp.public());
    let msg = IntentMessage::new(
        Intent::default(),
        PersonalMessage {
            message: "Hello".as_bytes().to_vec(),
        },
    );
    let sig = Signature::new_secure(&msg, &kp);
    assert!(sig.verify_secure_generic(&msg, addr).is_ok());
}
