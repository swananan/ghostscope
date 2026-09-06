//! C-compatible integer rules used by the GhostScope expression language.
//!
//! These are script evaluation semantics over DWARF integer representations,
//! not dispatch rules for C compilation units.

use crate::TypeInfo;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CIntegerComparisonType {
    pub size: u64,
    pub is_unsigned: bool,
    /// Effective value width for bitfields; storage bytes alone lose promotion rules.
    pub bitfield_width: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CIntegerComparisonPlan {
    pub size: u64,
    pub is_unsigned: bool,
}

impl CIntegerComparisonType {
    pub fn promoted(self) -> Self {
        let fits_int = self.bitfield_width.map_or(self.size < 4, |width| {
            width < 32 || (width == 32 && !self.is_unsigned)
        });
        if fits_int {
            Self {
                size: 4,
                is_unsigned: false,
                bitfield_width: None,
            }
        } else {
            self
        }
    }

    pub fn signed_i64() -> Self {
        Self {
            size: 8,
            is_unsigned: false,
            bitfield_width: None,
        }
    }
}

pub fn c_integer_comparison_type(ty: &TypeInfo) -> Option<CIntegerComparisonType> {
    match ty {
        TypeInfo::BaseType { encoding, size, .. } => {
            let is_unsigned = *encoding == crate::constants::DW_ATE_unsigned.0 as u16
                || *encoding == crate::constants::DW_ATE_unsigned_char.0 as u16;
            let is_signed = *encoding == crate::constants::DW_ATE_signed.0 as u16
                || *encoding == crate::constants::DW_ATE_signed_char.0 as u16
                || *encoding == crate::constants::DW_ATE_boolean.0 as u16;
            (is_unsigned || is_signed).then_some(CIntegerComparisonType {
                size: *size,
                is_unsigned,
                bitfield_width: None,
            })
        }
        TypeInfo::EnumType {
            base_type, size, ..
        }
        | TypeInfo::ScopedEnumType {
            base_type, size, ..
        } => c_integer_comparison_type(base_type).map(|mut ty| {
            if ty.size == 0 {
                ty.size = *size;
            }
            ty
        }),
        TypeInfo::BitfieldType {
            underlying_type,
            bit_size,
            ..
        } => c_integer_comparison_type(underlying_type).map(|mut ty| {
            ty.size = (*bit_size as u64).max(1).div_ceil(8);
            ty.bitfield_width = Some(*bit_size);
            ty
        }),
        TypeInfo::TypedefType {
            underlying_type, ..
        }
        | TypeInfo::QualifiedType {
            underlying_type, ..
        } => c_integer_comparison_type(underlying_type),
        _ => None,
    }
}

pub fn is_c_signed_integer_type(ty: &TypeInfo) -> bool {
    match ty {
        TypeInfo::BaseType { encoding, .. } => {
            *encoding == crate::constants::DW_ATE_signed.0 as u16
                || *encoding == crate::constants::DW_ATE_signed_char.0 as u16
        }
        TypeInfo::EnumType { base_type, .. } | TypeInfo::ScopedEnumType { base_type, .. } => {
            is_c_signed_integer_type(base_type)
        }
        TypeInfo::BitfieldType {
            underlying_type, ..
        } => is_c_signed_integer_type(underlying_type),
        TypeInfo::TypedefType {
            underlying_type, ..
        }
        | TypeInfo::QualifiedType {
            underlying_type, ..
        } => is_c_signed_integer_type(underlying_type),
        _ => false,
    }
}

pub fn usual_c_arithmetic_comparison_plan(
    left: CIntegerComparisonType,
    right: CIntegerComparisonType,
) -> CIntegerComparisonPlan {
    let left = left.promoted();
    let right = right.promoted();
    if left.is_unsigned == right.is_unsigned {
        return CIntegerComparisonPlan {
            size: left.size.max(right.size),
            is_unsigned: left.is_unsigned,
        };
    }

    let unsigned = if left.is_unsigned { left } else { right };
    let signed = if left.is_unsigned { right } else { left };
    if unsigned.size >= signed.size {
        CIntegerComparisonPlan {
            size: unsigned.size,
            is_unsigned: true,
        }
    } else {
        CIntegerComparisonPlan {
            size: signed.size,
            is_unsigned: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int_type(name: &str, size: u64, encoding: u16) -> TypeInfo {
        TypeInfo::BaseType {
            name: name.to_string(),
            size,
            encoding,
        }
    }

    fn signed_int() -> TypeInfo {
        int_type("int", 4, crate::constants::DW_ATE_signed.0 as u16)
    }

    #[test]
    fn bitfield_promotions_use_value_width_at_the_int_boundary() {
        for unsigned in [false, true] {
            for width in [1, 24, 25, 31, 32] {
                let bitfield = TypeInfo::BitfieldType {
                    underlying_type: Box::new(int_type(
                        if unsigned { "unsigned int" } else { "int" },
                        4,
                        if unsigned {
                            crate::constants::DW_ATE_unsigned.0 as u16
                        } else {
                            crate::constants::DW_ATE_signed.0 as u16
                        },
                    )),
                    bit_offset: 0,
                    bit_size: width,
                };
                let ty = c_integer_comparison_type(&bitfield).unwrap();
                assert_eq!(ty.is_unsigned, unsigned, "storage signedness is unchanged");
                let plan = usual_c_arithmetic_comparison_plan(
                    c_integer_comparison_type(&signed_int()).unwrap(),
                    ty,
                );
                assert_eq!(plan.size, 4);
                assert_eq!(plan.is_unsigned, unsigned && width == 32);
                assert_eq!(ty.promoted().promoted(), ty.promoted());
            }
        }
    }

    #[test]
    fn integer_comparison_type_handles_enums_and_bitfields() {
        let enum_type = TypeInfo::EnumType {
            name: "Mode".to_string(),
            size: 4,
            variants: vec![],
            base_type: Box::new(int_type(
                "unsigned int",
                0,
                crate::constants::DW_ATE_unsigned.0 as u16,
            )),
        };
        assert_eq!(
            c_integer_comparison_type(&enum_type),
            Some(CIntegerComparisonType {
                size: 4,
                is_unsigned: true,
                bitfield_width: None,
            })
        );

        let bitfield_type = TypeInfo::BitfieldType {
            underlying_type: Box::new(signed_int()),
            bit_offset: 0,
            bit_size: 9,
        };
        assert_eq!(
            c_integer_comparison_type(&bitfield_type),
            Some(CIntegerComparisonType {
                size: 2,
                is_unsigned: false,
                bitfield_width: Some(9),
            })
        );
    }

    #[test]
    fn signed_integer_classification_excludes_boolean() {
        let bool_type = int_type("bool", 1, crate::constants::DW_ATE_boolean.0 as u16);
        assert_eq!(
            c_integer_comparison_type(&bool_type),
            Some(CIntegerComparisonType {
                size: 1,
                is_unsigned: false,
                bitfield_width: None,
            })
        );
        assert!(!is_c_signed_integer_type(&bool_type));
        assert!(is_c_signed_integer_type(&signed_int()));
    }

    #[test]
    fn usual_comparison_plan_applies_integer_promotions() {
        let u8_type = CIntegerComparisonType {
            size: 1,
            is_unsigned: true,
            bitfield_width: None,
        };
        let i8_type = CIntegerComparisonType {
            size: 1,
            is_unsigned: false,
            bitfield_width: None,
        };

        assert_eq!(
            usual_c_arithmetic_comparison_plan(u8_type, i8_type),
            CIntegerComparisonPlan {
                size: 4,
                is_unsigned: false,
            }
        );
    }

    #[test]
    fn usual_comparison_plan_respects_unsigned_rank() {
        let u64_type = CIntegerComparisonType {
            size: 8,
            is_unsigned: true,
            bitfield_width: None,
        };
        let i32_type = CIntegerComparisonType {
            size: 4,
            is_unsigned: false,
            bitfield_width: None,
        };

        assert_eq!(
            usual_c_arithmetic_comparison_plan(u64_type, i32_type),
            CIntegerComparisonPlan {
                size: 8,
                is_unsigned: true,
            }
        );
    }
}
