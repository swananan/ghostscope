use super::ExpressionEvaluator;
use crate::core::{
    AddressExpr, Availability, CfaResult, DirectValueResult, LocationResult, MemoryAccessSize,
    ParsedLocation, PieceLocation, PieceResult, PlanExprOp, RawExpressionResult, VariableLocation,
};
use gimli::constants;
use gimli::RunTimeEndian;

fn test_encoding() -> gimli::Encoding {
    gimli::Encoding {
        format: gimli::Format::Dwarf32,
        version: 5,
        address_size: 8,
    }
}

fn encode_uleb(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

#[test]
fn converts_register_address_result_to_semantic_location() {
    let result = RawExpressionResult::MemoryLocation(LocationResult::RegisterAddress {
        register: 6,
        offset: Some(-16),
        size: None,
    });

    assert_eq!(
        ExpressionEvaluator::variable_location_from_result(&result),
        VariableLocation::RegisterAddress {
            dwarf_reg: 6,
            offset: -16
        }
    );
}

#[test]
fn converts_absolute_address_value_as_rebasable_value() {
    let result = RawExpressionResult::DirectValue(DirectValueResult::AbsoluteAddress(0x1234));

    assert_eq!(
        ExpressionEvaluator::variable_location_from_result(&result),
        VariableLocation::AbsoluteAddressValue(AddressExpr::constant(0x1234))
    );
}

#[test]
fn converts_composite_result_to_semantic_pieces() {
    let result = RawExpressionResult::Composite(vec![PieceResult {
        location: RawExpressionResult::DirectValue(DirectValueResult::RegisterValue(0)),
        size: 4,
        bit_offset: Some(32),
    }]);

    assert_eq!(
        ExpressionEvaluator::variable_location_from_result(&result),
        VariableLocation::Pieces(vec![PieceLocation {
            bit_offset: 32,
            bit_size: 32,
            location: Box::new(VariableLocation::RegisterValue { dwarf_reg: 0 }),
        }])
    );
}

fn encode_sleb(mut value: i64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value as u8) & 0x7f;
        value >>= 7;
        let sign_bit_set = (byte & 0x40) != 0;
        let done = (value == 0 && !sign_bit_set) || (value == -1 && sign_bit_set);
        if !done {
            byte |= 0x80;
        }
        out.push(byte);
        if done {
            break;
        }
    }
    out
}

fn parse_test_expr(bytes: &[u8]) -> anyhow::Result<RawExpressionResult> {
    ExpressionEvaluator::parse_expression_with_context(
        bytes,
        RunTimeEndian::Little,
        test_encoding(),
        None,
        None,
        0,
        None,
        None,
        None,
        0,
    )
}

fn lower_test_expr(bytes: &[u8]) -> anyhow::Result<ParsedLocation> {
    let raw = parse_test_expr(bytes)?;
    Ok(ExpressionEvaluator::parsed_location_from_result(&raw))
}

fn addr_expr(address: u64) -> Vec<u8> {
    let mut bytes = vec![constants::DW_OP_addr.0];
    bytes.extend(address.to_le_bytes());
    bytes
}

fn regx_expr(register: u64) -> Vec<u8> {
    let mut bytes = vec![constants::DW_OP_regx.0];
    bytes.extend(encode_uleb(register));
    bytes
}

fn bregx_expr(register: u64, offset: i64) -> Vec<u8> {
    let mut bytes = vec![constants::DW_OP_bregx.0];
    bytes.extend(encode_uleb(register));
    bytes.extend(encode_sleb(offset));
    bytes
}

#[test]
fn dwarf_expression_lowering_returns_register_value_parsed_location() {
    let parsed = lower_test_expr(&[constants::DW_OP_reg5.0])
        .expect("DW_OP_reg5 should lower to ParsedLocation");

    assert_eq!(
        parsed.location,
        VariableLocation::RegisterValue { dwarf_reg: 5 }
    );
    assert_eq!(parsed.availability, Availability::Available);
}

#[test]
fn dwarf_expression_lowering_returns_register_address_parsed_location() {
    let parsed =
        lower_test_expr(&bregx_expr(6, -16)).expect("DW_OP_bregx should lower to ParsedLocation");

    assert_eq!(
        parsed.location,
        VariableLocation::RegisterAddress {
            dwarf_reg: 6,
            offset: -16
        }
    );
    assert_eq!(parsed.availability, Availability::Available);
}

#[test]
fn dwarf_expression_lowering_returns_stack_value_parsed_location() {
    let parsed = lower_test_expr(&[constants::DW_OP_lit1.0, constants::DW_OP_stack_value.0])
        .expect("DW_OP_stack_value should lower to ParsedLocation");

    assert_eq!(
        parsed.location,
        VariableLocation::ComputedValue(vec![PlanExprOp::PushConstant(1)])
    );
    assert_eq!(parsed.availability, Availability::Available);
}

#[test]
fn dwarf_expression_lowering_marks_mixed_pieces_partially_available() {
    let mut bytes = vec![constants::DW_OP_piece.0];
    bytes.extend(encode_uleb(4));
    bytes.push(constants::DW_OP_reg0.0);
    bytes.push(constants::DW_OP_piece.0);
    bytes.extend(encode_uleb(4));

    let parsed = lower_test_expr(&bytes)
        .expect("mixed DW_OP_piece expression should lower to ParsedLocation");

    assert_eq!(
        parsed.location,
        VariableLocation::Pieces(vec![
            PieceLocation {
                bit_offset: 0,
                bit_size: 32,
                location: Box::new(VariableLocation::OptimizedOut),
            },
            PieceLocation {
                bit_offset: 32,
                bit_size: 32,
                location: Box::new(VariableLocation::RegisterValue { dwarf_reg: 0 }),
            },
        ])
    );
    assert_eq!(parsed.availability, Availability::PartiallyAvailable);
}

#[test]
fn dwarf_op_supported_coverage_matrix() {
    let cases = vec![
        (
            "DW_OP_regN",
            vec![constants::DW_OP_reg5.0],
            RawExpressionResult::DirectValue(DirectValueResult::RegisterValue(5)),
        ),
        (
            "DW_OP_regx",
            regx_expr(33),
            RawExpressionResult::DirectValue(DirectValueResult::RegisterValue(33)),
        ),
        (
            "DW_OP_bregN",
            {
                let mut bytes = vec![constants::DW_OP_breg7.0];
                bytes.extend(encode_sleb(8));
                bytes
            },
            RawExpressionResult::MemoryLocation(LocationResult::RegisterAddress {
                register: 7,
                offset: Some(8),
                size: None,
            }),
        ),
        (
            "DW_OP_bregx",
            bregx_expr(33, -2),
            RawExpressionResult::MemoryLocation(LocationResult::RegisterAddress {
                register: 33,
                offset: Some(-2),
                size: None,
            }),
        ),
        (
            "DW_OP_addr",
            addr_expr(0x1234),
            RawExpressionResult::MemoryLocation(LocationResult::Address(0x1234)),
        ),
        (
            "DW_OP_stack_value",
            vec![constants::DW_OP_lit1.0, constants::DW_OP_stack_value.0],
            RawExpressionResult::DirectValue(DirectValueResult::Constant(1)),
        ),
        (
            "DW_OP_addr stack value",
            {
                let mut bytes = addr_expr(0x1234);
                bytes.push(constants::DW_OP_stack_value.0);
                bytes
            },
            RawExpressionResult::DirectValue(DirectValueResult::AbsoluteAddress(0x1234)),
        ),
        (
            "arithmetic stack value subset",
            vec![
                constants::DW_OP_lit1.0,
                constants::DW_OP_lit2.0,
                constants::DW_OP_plus.0,
                constants::DW_OP_stack_value.0,
            ],
            RawExpressionResult::DirectValue(DirectValueResult::ComputedValue {
                steps: vec![
                    PlanExprOp::PushConstant(1),
                    PlanExprOp::PushConstant(2),
                    PlanExprOp::Add,
                ],
                result_size: MemoryAccessSize::U64,
            }),
        ),
        (
            "DW_OP_implicit_value",
            vec![constants::DW_OP_implicit_value.0, 3, 0xaa, 0xbb, 0xcc],
            RawExpressionResult::DirectValue(DirectValueResult::ImplicitValue(vec![
                0xaa, 0xbb, 0xcc,
            ])),
        ),
        (
            "DW_OP_piece split stack values",
            {
                let mut bytes = vec![constants::DW_OP_breg5.0];
                bytes.extend(encode_sleb(1));
                bytes.push(constants::DW_OP_stack_value.0);
                bytes.push(constants::DW_OP_piece.0);
                bytes.extend(encode_uleb(4));
                bytes.push(constants::DW_OP_breg5.0);
                bytes.extend(encode_sleb(2));
                bytes.push(constants::DW_OP_stack_value.0);
                bytes.push(constants::DW_OP_piece.0);
                bytes.extend(encode_uleb(4));
                bytes
            },
            RawExpressionResult::Composite(vec![
                PieceResult {
                    location: RawExpressionResult::DirectValue(DirectValueResult::ComputedValue {
                        steps: vec![
                            PlanExprOp::LoadRegister(5),
                            PlanExprOp::PushConstant(1),
                            PlanExprOp::Add,
                        ],
                        result_size: MemoryAccessSize::U64,
                    }),
                    size: 4,
                    bit_offset: Some(0),
                },
                PieceResult {
                    location: RawExpressionResult::DirectValue(DirectValueResult::ComputedValue {
                        steps: vec![
                            PlanExprOp::LoadRegister(5),
                            PlanExprOp::PushConstant(2),
                            PlanExprOp::Add,
                        ],
                        result_size: MemoryAccessSize::U64,
                    }),
                    size: 4,
                    bit_offset: Some(32),
                },
            ]),
        ),
        (
            "DW_OP_piece empty segment",
            {
                let mut bytes = vec![constants::DW_OP_piece.0];
                bytes.extend(encode_uleb(4));
                bytes
            },
            RawExpressionResult::Composite(vec![PieceResult {
                location: RawExpressionResult::Optimized,
                size: 4,
                bit_offset: Some(0),
            }]),
        ),
    ];

    for (name, bytes, expected) in cases {
        let result = parse_test_expr(&bytes).unwrap_or_else(|error| {
            panic!("{name} should parse successfully, bytes={bytes:?}: {error}")
        });
        assert_eq!(result, expected, "{name} lowered incorrectly");
    }
}

#[test]
fn dwarf_op_fbreg_coverage_uses_cfa_provider() {
    let get_cfa = |_address| {
        Ok(Some(CfaResult::RegisterPlusOffset {
            register: 7,
            offset: 16,
        }))
    };
    let mut expr = vec![constants::DW_OP_fbreg.0];
    expr.extend(encode_sleb(4));

    let result = ExpressionEvaluator::parse_expression_with_context(
        &expr,
        RunTimeEndian::Little,
        test_encoding(),
        None,
        None,
        0,
        Some(&get_cfa),
        None,
        None,
        0,
    )
    .expect("DW_OP_fbreg should parse with a CFA provider");

    assert_eq!(
        result,
        RawExpressionResult::MemoryLocation(LocationResult::RegisterAddress {
            register: 7,
            offset: Some(20),
            size: None,
        })
    );
}

#[test]
fn dwarf_frame_base_reg_lowers_to_register_cfa() {
    let cfa = ExpressionEvaluator::raw_expression_result_to_cfa(RawExpressionResult::DirectValue(
        DirectValueResult::RegisterValue(6),
    ));

    assert_eq!(
        cfa,
        Some(CfaResult::RegisterPlusOffset {
            register: 6,
            offset: 0,
        })
    );
}

#[test]
fn dwarf_op_unsupported_diagnostic_matrix_names_ops() {
    let cases = vec![
        (
            "DW_OP_drop",
            vec![
                constants::DW_OP_lit1.0,
                constants::DW_OP_drop.0,
                constants::DW_OP_stack_value.0,
            ],
            "DW_OP_drop",
        ),
        (
            "DW_OP_bit_piece",
            {
                let mut bytes = vec![constants::DW_OP_lit1.0, constants::DW_OP_bit_piece.0];
                bytes.extend(encode_uleb(8));
                bytes.extend(encode_uleb(0));
                bytes
            },
            "DW_OP_bit_piece",
        ),
        (
            "DW_OP_addrx",
            {
                let mut bytes = vec![constants::DW_OP_addrx.0];
                bytes.extend(encode_uleb(0));
                bytes
            },
            "DW_OP_addrx",
        ),
        (
            "DW_OP_bra",
            vec![
                constants::DW_OP_lit1.0,
                constants::DW_OP_bra.0,
                0,
                0,
                constants::DW_OP_stack_value.0,
            ],
            "DW_OP_bra",
        ),
    ];

    for (name, bytes, expected_op) in cases {
        let error = match parse_test_expr(&bytes) {
            Ok(result) => panic!("{name} should be unsupported, got {result:?}"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            message.contains(expected_op),
            "{name} diagnostic should mention {expected_op}, got: {message}"
        );
        assert!(
            message.contains("unsupported"),
            "{name} diagnostic should be explicit, got: {message}"
        );
        assert_eq!(
            crate::dwarf_expr::ops::unsupported_op_from_error(&error),
            Some(expected_op),
            "{name} diagnostic should carry a typed unsupported-op cause"
        );
    }
}

#[test]
fn implicit_pointer_to_static_storage_preserves_absolute_address_semantics() {
    let result = ExpressionEvaluator::addressable_location_to_pointer_value(
        RawExpressionResult::MemoryLocation(LocationResult::Address(0x1234)),
        0x10,
    )
    .expect("static address should convert to an implicit pointer value");

    assert_eq!(
        result,
        RawExpressionResult::DirectValue(DirectValueResult::AbsoluteAddress(0x1244))
    );
}

#[test]
fn implicit_pointer_accepts_target_absolute_address_value() {
    let result = ExpressionEvaluator::addressable_location_to_pointer_value(
        RawExpressionResult::DirectValue(DirectValueResult::AbsoluteAddress(0x1234)),
        0x10,
    )
    .expect("static address values should convert to an implicit pointer value");

    assert_eq!(
        result,
        RawExpressionResult::DirectValue(DirectValueResult::AbsoluteAddress(0x1244))
    );
}

#[test]
fn multi_op_expression_rejects_invalid_opcode_after_valid_prefix() {
    let expr_bytes = [
        constants::DW_OP_lit1.0,
        0xff,
        constants::DW_OP_stack_value.0,
    ];

    let error = ExpressionEvaluator::parse_expression_with_context(
        &expr_bytes,
        RunTimeEndian::Little,
        test_encoding(),
        None,
        None,
        0,
        None,
        None,
        None,
        0,
    )
    .expect_err("invalid opcode after a valid prefix must not return a value");

    assert!(
        error.to_string().contains("DWARF expression"),
        "unexpected error: {error}"
    );
}

#[test]
fn multi_op_expression_rejects_unsupported_operation_after_valid_prefix() {
    let expr_bytes = [
        constants::DW_OP_lit1.0,
        constants::DW_OP_drop.0,
        constants::DW_OP_stack_value.0,
    ];

    let error = ExpressionEvaluator::parse_expression_with_context(
        &expr_bytes,
        RunTimeEndian::Little,
        test_encoding(),
        None,
        None,
        0,
        None,
        None,
        None,
        0,
    )
    .expect_err("unsupported operation after a valid prefix must not return a value");

    assert!(
        error.to_string().contains("unsupported"),
        "unexpected error: {error}"
    );
}

#[test]
fn single_fbreg_fast_path_saturates_cfa_offset_addition() {
    let get_cfa = |_address| {
        Ok(Some(CfaResult::RegisterPlusOffset {
            register: 7,
            offset: i64::MAX - 3,
        }))
    };

    let result = ExpressionEvaluator::parse_expression_with_context(
        &[0x91, 0x0a],
        RunTimeEndian::Little,
        test_encoding(),
        None,
        None,
        0,
        Some(&get_cfa),
        None,
        None,
        0,
    )
    .expect("single DW_OP_fbreg should parse");

    assert_eq!(
        result,
        RawExpressionResult::MemoryLocation(LocationResult::RegisterAddress {
            register: 7,
            offset: Some(i64::MAX),
            size: None,
        })
    );
}

#[test]
fn big_endian_dw_op_addr_preserves_absolute_address() {
    let expr_bytes = [0x03, 0, 0, 0, 0, 0, 0, 0x12, 0x34];
    let result = ExpressionEvaluator::parse_expression_with_context(
        &expr_bytes,
        gimli::RunTimeEndian::Big,
        test_encoding(),
        None,
        None,
        0,
        None,
        None,
        None,
        0,
    )
    .expect("big-endian DW_OP_addr should parse");

    assert_eq!(
        result,
        RawExpressionResult::MemoryLocation(LocationResult::Address(0x1234))
    );
}
