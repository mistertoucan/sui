// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    crypto::{CompressedSignature, SuiSignature},
    sui_serde::SuiBitmap,
};
pub use enum_dispatch::enum_dispatch;
use fastcrypto::{
    ed25519::Ed25519PublicKey, encoding::Base64, secp256k1::Secp256k1PublicKey,
    secp256r1::Secp256r1PublicKey, traits::ToFromBytes, Verifier,
};
use roaring::RoaringBitmap;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::hash::{Hash, Hasher};

use crate::{
    base_types::SuiAddress,
    crypto::{PublicKey, Signature},
    error::SuiError,
    intent::IntentMessage,
};

#[cfg(test)]
#[path = "unit_tests/multisig_tests.rs"]
mod multisig_tests;

pub type WeightUnit = u8;
pub type ThresholdUnit = u16;
pub const MAX_PKS_IN_MULTISIG: usize = 10;
#[enum_dispatch]
pub trait AuthenticatorTrait {
    fn verify_secure_generic<T>(
        &self,
        value: &IntentMessage<T>,
        author: SuiAddress,
    ) -> Result<(), SuiError>
    where
        T: Serialize;
}

#[enum_dispatch(AuthenticatorTrait)]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema, Hash)]
#[serde(untagged)]
pub enum GenericSignature {
    MultiSignature,
    Signature,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct MultiSignature {
    sigs: Vec<CompressedSignature>,
    #[schemars(with = "Base64")]
    #[serde_as(as = "SuiBitmap")]
    bitmap: RoaringBitmap,
    multi_pk: MultiPublicKey,
}

impl PartialEq for MultiSignature {
    fn eq(&self, other: &Self) -> bool {
        self.sigs == other.sigs && self.bitmap == other.bitmap && self.multi_pk == other.multi_pk
    }
}
impl Eq for MultiSignature {}

impl Hash for MultiSignature {
    fn hash<H: Hasher>(&self, _state: &mut H) {
        todo!()
    }
}

impl MultiSignature {
    pub fn size(&self) -> usize {
        self.sigs.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MultiPublicKey {
    pk_map: Vec<(PublicKey, WeightUnit)>,
    threshold: ThresholdUnit,
}

impl MultiPublicKey {
    pub fn new(
        pks: Vec<PublicKey>,
        weights: Vec<WeightUnit>,
        threshold: ThresholdUnit,
    ) -> Result<Self, SuiError> {
        if pks.len() != weights.len() || pks.len() > 10 {
            return Err(SuiError::InvalidSignature {
                error: "Invalid number of public keys".to_string(),
            });
        }
        Ok(MultiPublicKey {
            pk_map: pks.into_iter().zip(weights.into_iter()).collect(),
            threshold,
        })
    }

    pub fn get_index(&self, pk: PublicKey) -> Option<u32> {
        self.pk_map.iter().position(|x| x.0 == pk).map(|x| x as u32)
    }

    pub fn threshold(&self) -> &ThresholdUnit {
        &self.threshold
    }

    pub fn pubkeys(&self) -> &Vec<(PublicKey, WeightUnit)> {
        &self.pk_map
    }
}

impl AuthenticatorTrait for MultiSignature {
    fn verify_secure_generic<T>(
        &self,
        value: &IntentMessage<T>,
        author: SuiAddress,
    ) -> Result<(), SuiError>
    where
        T: Serialize,
    {
        if self.multi_pk.pk_map.len() > MAX_PKS_IN_MULTISIG {
            return Err(SuiError::InvalidSignature {
                error: "Invalid number of public keys".to_string(),
            });
        }
        if (self.multi_pk.pk_map.len() as u16) < self.multi_pk.threshold {
            return Err(SuiError::InvalidSignature {
                error: "Invalid number of public keys".to_string(),
            });
        }

        if <SuiAddress as From<MultiPublicKey>>::from(self.multi_pk.clone()) != author {
            return Err(SuiError::InvalidSignature {
                error: "Invalid address".to_string(),
            });
        }
        let mut weight_sum = 0;
        let msg = &bcs::to_bytes(value).unwrap();

        for (sig, i) in self.sigs.iter().zip(&self.bitmap) {
            let pk_map = self
                .multi_pk
                .pk_map
                .get(i as usize)
                .ok_or(SuiError::InvalidSignature {
                    error: "Invalid public keys index".to_string(),
                })
                .unwrap();
            let res = match sig {
                CompressedSignature::Ed25519(s) => {
                    let pk = Ed25519PublicKey::from_bytes(pk_map.0.as_ref())
                        .map_err(|_| SuiError::InvalidSignature {
                            error: "Invalid public key".to_string(),
                        })
                        .unwrap();
                    pk.verify(msg, s)
                }
                CompressedSignature::Secp256k1(s) => {
                    let pk = Secp256k1PublicKey::from_bytes(pk_map.0.as_ref())
                        .map_err(|_| SuiError::InvalidSignature {
                            error: "Invalid public key".to_string(),
                        })
                        .unwrap();
                    pk.verify(msg, s)
                }
                CompressedSignature::Secp256r1(s) => {
                    let pk = Secp256r1PublicKey::from_bytes(pk_map.0.as_ref()).map_err(|_| {
                        SuiError::InvalidSignature {
                            error: "Invalid public key".to_string(),
                        }
                    })?;
                    pk.verify(msg, s)
                }
            };
            if res.is_ok() {
                weight_sum += pk_map.1 as u16;
            }
        }

        if weight_sum >= self.multi_pk.threshold {
            Ok(())
        } else {
            Err(SuiError::InvalidSignature {
                error: "Insufficient weight".to_string(),
            })
        }
    }
}
impl MultiSignature {
    pub fn combine(full_sigs: Vec<Signature>, multi_pk: MultiPublicKey) -> Result<Self, SuiError> {
        let mut bitmap = RoaringBitmap::new();
        let mut sigs = Vec::new();
        full_sigs.iter().for_each(|s| {
            bitmap.insert(multi_pk.get_index(s.to_public_key()).unwrap());
            sigs.push(s.to_compressed());
        });

        Ok(MultiSignature {
            sigs,
            bitmap,
            multi_pk,
        })
    }
}

/// Port to the verify_secure defined on Single Signature.
impl AuthenticatorTrait for Signature {
    fn verify_secure_generic<T>(
        &self,
        value: &IntentMessage<T>,
        author: SuiAddress,
    ) -> Result<(), SuiError>
    where
        T: Serialize,
    {
        self.verify_secure(value, author)
    }
}
