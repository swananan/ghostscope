use super::*;

/// One byte-aligned contribution to a reconstructed value. Memory sources
/// denote storage, while value sources contribute their least significant bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedPiece {
    pub byte_offset: usize,
    pub byte_size: usize,
    pub source: PlannedPieceSource,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PlannedPieceSource {
    Value(PlannedValue),
    Memory(PlannedAddress),
}

pub(super) fn plan_pieces(
    pieces: &[PieceLocation],
    dwarf_type: Option<&TypeInfo>,
) -> Result<Vec<PlannedPiece>> {
    let size = dwarf_type
        .map(TypeInfo::size)
        .filter(|size| *size > 0)
        .ok_or_else(|| anyhow::anyhow!("split variable has no known nonzero type size"))?;
    let size = usize::try_from(size)?;
    let mut offset = 0usize;
    let mut planned = Vec::new();
    for piece in pieces {
        if !piece.bit_offset.is_multiple_of(8) || !piece.bit_size.is_multiple_of(8) {
            anyhow::bail!("split variable pieces must be byte-aligned");
        }
        let byte_offset = (piece.bit_offset / 8) as usize;
        let byte_size = (piece.bit_size / 8) as usize;
        if byte_offset != offset {
            anyhow::bail!("split variable pieces contain a gap or overlap at byte {offset}");
        }
        offset = offset
            .checked_add(byte_size)
            .filter(|end| *end <= size)
            .ok_or_else(|| anyhow::anyhow!("split variable pieces exceed its {size}-byte type"))?;
        if byte_size == 0 {
            continue;
        }
        let location = piece.location.as_ref();
        let source = match location {
            VariableLocation::ImplicitValue(bytes) => {
                if bytes.len() < byte_size {
                    anyhow::bail!(
                        "split variable implicit piece is shorter than {byte_size} bytes"
                    );
                }
                PlannedPieceSource::Value(PlannedValue::ImplicitBytes(bytes[..byte_size].to_vec()))
            }
            VariableLocation::Address(_)
            | VariableLocation::RegisterAddress { .. }
            | VariableLocation::FrameBaseRelative { .. }
            | VariableLocation::ComputedAddress(_) => {
                let address = PlannedAddress::from_location(location.clone())
                    .ok_or_else(|| anyhow::anyhow!("split variable memory piece has no address"))?;
                PlannedPieceSource::Memory(address)
            }
            _ => {
                if byte_size > 8 {
                    anyhow::bail!("split variable value piece exceeds one 8-byte register");
                }
                let value = PlannedValue::from_location(location.clone(), MemoryAccessSize::U64)
                    .ok_or_else(|| anyhow::anyhow!("split variable piece at byte {byte_offset} is unavailable or unsupported"))?;
                PlannedPieceSource::Value(value)
            }
        };
        planned.push(PlannedPiece {
            byte_offset,
            byte_size,
            source,
        });
    }
    if offset != size {
        anyhow::bail!("split variable pieces cover {offset} of {size} bytes");
    }
    Ok(planned)
}
