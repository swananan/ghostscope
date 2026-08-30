use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ghostscope_protocol::streaming_parser::StreamingTraceParser;
use ghostscope_protocol::trace_event::{
    EndInstructionData, InstructionHeader, InstructionType, PrintComplexVariableData,
    TraceEventHeader, TraceEventMessage, VariableStatus,
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

criterion_group!(benches, benchmark_streaming_parser);
criterion_main!(benches);
