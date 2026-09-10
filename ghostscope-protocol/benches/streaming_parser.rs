use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ghostscope_protocol::streaming_parser::StreamingTraceParser;
use ghostscope_protocol::trace_event::{
    EndInstructionData, InstructionHeader, InstructionType, PrintComplexFormatData,
    PrintComplexVariableData, TraceEventHeader, TraceEventMessage, VariableStatus,
};
use ghostscope_protocol::{TraceContext, TypeInfo};
use std::hint::black_box;
use std::mem::size_of;
use zerocopy::IntoBytes;

const EVENT_SIZE: usize = 32 * 1024;
const INSTRUCTION_COUNTS: [usize; 3] = [1, 16, 128];

fn append_instruction_header(buffer: &mut Vec<u8>, instruction_type: InstructionType, len: usize) {
    buffer.push(instruction_type as u8);
    buffer.extend_from_slice(
        &u16::try_from(len)
            .expect("benchmark instruction payload fits in u16")
            .to_le_bytes(),
    );
    buffer.push(0);
}

fn build_event(instruction_count: usize) -> Vec<u8> {
    let fixed_size = size_of::<TraceEventHeader>()
        + size_of::<TraceEventMessage>()
        + size_of::<InstructionHeader>()
        + size_of::<EndInstructionData>()
        + instruction_count
            * (size_of::<InstructionHeader>() + size_of::<PrintComplexVariableData>());
    let total_data_size = EVENT_SIZE
        .checked_sub(fixed_size)
        .expect("benchmark event metadata fits in 32 KiB");
    let data_size = total_data_size / instruction_count;
    let instructions_with_extra_byte = total_data_size % instruction_count;

    let mut event = Vec::with_capacity(EVENT_SIZE);
    event.extend_from_slice(
        TraceEventHeader {
            magic: ghostscope_protocol::consts::MAGIC,
            reserved: 0,
            generation: 0,
        }
        .as_bytes(),
    );
    event.extend_from_slice(
        TraceEventMessage {
            trace_id: 1,
            timestamp: 2,
            pid: 3,
            tid: 4,
        }
        .as_bytes(),
    );

    for index in 0..instruction_count {
        let data_size = data_size + usize::from(index < instructions_with_extra_byte);
        let instruction_data_size = size_of::<PrintComplexVariableData>() + data_size;
        append_instruction_header(
            &mut event,
            InstructionType::PrintComplexVariable,
            instruction_data_size,
        );

        event.extend_from_slice(&0u16.to_le_bytes()); // var_name_index
        event.extend_from_slice(&0u16.to_le_bytes()); // type_index
        event.push(0); // access_path_len
        event.push(VariableStatus::Truncated as u8);
        event.extend_from_slice(
            &u16::try_from(data_size)
                .expect("benchmark variable payload fits in u16")
                .to_le_bytes(),
        );
        event.resize(event.len() + data_size, 0xa5);
    }

    append_instruction_header(
        &mut event,
        InstructionType::EndInstruction,
        size_of::<EndInstructionData>(),
    );
    event.extend_from_slice(
        &u16::try_from(instruction_count)
            .expect("benchmark instruction count fits in u16")
            .to_le_bytes(),
    );
    event.push(0); // execution_status
    event.push(0); // reserved

    assert_eq!(event.len(), EVENT_SIZE);
    event
}

fn trace_context() -> TraceContext {
    let mut trace_context = TraceContext::new();
    trace_context
        .add_variable_name("payload".to_string())
        .expect("add benchmark variable name");
    trace_context
        .add_type(TypeInfo::UnknownType {
            name: "payload".to_string(),
        })
        .expect("add benchmark type");
    trace_context
}

fn benchmark_streaming_parser(c: &mut Criterion) {
    let trace_context = trace_context();
    let mut group = c.benchmark_group("streaming_parser/32_kib_event");
    group.throughput(Throughput::Bytes(EVENT_SIZE as u64));

    for instruction_count in INSTRUCTION_COUNTS {
        let event = build_event(instruction_count);
        group.bench_with_input(
            BenchmarkId::new("instructions", instruction_count),
            &event,
            |b, event| {
                let mut parser = StreamingTraceParser::new();
                b.iter(|| {
                    let parsed = parser
                        .process_segment(black_box(event.as_slice()), black_box(&trace_context))
                        .expect("benchmark event parses successfully")
                        .expect("benchmark event is complete");
                    black_box(parsed);
                });
            },
        );
    }

    group.finish();
}

fn build_format_event(argument_count: u8, payload_size: usize) -> (TraceContext, Vec<u8>) {
    let mut context = TraceContext::new();
    context.add_variable_name("payload".into()).unwrap();
    let scalar = payload_size == 8;
    let ty = if scalar {
        TypeInfo::BaseType {
            name: "u64".into(),
            size: 8,
            encoding: gimli::constants::DW_ATE_unsigned.0 as u16,
        }
    } else {
        TypeInfo::ArrayType {
            element_type: Box::new(TypeInfo::BaseType {
                name: "char".into(),
                size: 1,
                encoding: gimli::constants::DW_ATE_unsigned_char.0 as u16,
            }),
            element_count: Some(payload_size as u64),
            total_size: Some(payload_size as u64),
        }
    };
    context.add_type(ty).unwrap();
    let slot = if scalar { "{}" } else { "{:s}" };
    context
        .add_string(
            (0..argument_count)
                .map(|index| format!("field{index}={slot}"))
                .collect::<Vec<_>>()
                .join(" "),
        )
        .unwrap();

    let mut arguments = Vec::new();
    for _ in 0..argument_count {
        arguments.extend_from_slice(&0u16.to_le_bytes()); // var_name_index
        arguments.extend_from_slice(&0u16.to_le_bytes()); // type_index
        let access_path = b".field";
        arguments.push(access_path.len() as u8);
        arguments.push(VariableStatus::Ok as u8);
        arguments.extend_from_slice(access_path);
        arguments.extend_from_slice(&(payload_size as u16).to_le_bytes());
        if scalar {
            arguments.extend_from_slice(&42u64.to_le_bytes());
        } else {
            // A fixed-size character buffer with a short NUL-terminated value.
            // Captured padding should not require a temporary copy for formatting.
            arguments.extend_from_slice(b"hello\0");
            arguments.resize(arguments.len() + payload_size - 6, 0);
        }
    }

    let mut event = Vec::new();
    event.extend_from_slice(
        TraceEventHeader {
            magic: ghostscope_protocol::consts::MAGIC,
            reserved: 0,
            generation: 0,
        }
        .as_bytes(),
    );
    event.extend_from_slice(
        TraceEventMessage {
            trace_id: 1,
            timestamp: 2,
            pid: 3,
            tid: 4,
        }
        .as_bytes(),
    );
    append_instruction_header(
        &mut event,
        InstructionType::PrintComplexFormat,
        size_of::<PrintComplexFormatData>() + arguments.len(),
    );
    event.extend_from_slice(&0u16.to_le_bytes()); // format_string_index
    event.push(argument_count);
    event.push(0);
    event.extend_from_slice(&arguments);
    append_instruction_header(
        &mut event,
        InstructionType::EndInstruction,
        size_of::<EndInstructionData>(),
    );
    event.extend_from_slice(&1u16.to_le_bytes());
    event.extend_from_slice(&[0, 0]);
    (context, event)
}

fn benchmark_complex_format(c: &mut Criterion) {
    let mut group = c.benchmark_group("streaming_parser/complex_format");
    for (name, argument_count, payload_size) in [
        ("scalar", 1, 8),
        ("scalar", 8, 8),
        ("char_buffer_256", 1, 256),
        ("char_buffer_4096", 1, 4096),
    ] {
        let (context, event) = build_format_event(argument_count, payload_size);
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new(name, argument_count),
            &event,
            |b, event| {
                let mut parser = StreamingTraceParser::new();
                b.iter(|| {
                    let parsed = parser
                        .process_segment(black_box(event), black_box(&context))
                        .expect("format event parses successfully")
                        .expect("format event is complete");
                    black_box(parsed);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    benchmark_streaming_parser,
    benchmark_complex_format
);
criterion_main!(benches);
