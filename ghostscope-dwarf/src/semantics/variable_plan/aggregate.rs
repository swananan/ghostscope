//! Byte projections of values which do not have a single target address.

use super::*;

impl VariableLocation {
    /// Select bytes in object order, preserving address versus value semantics.
    pub(crate) fn byte_range(&self, offset: u64, size: u64) -> Result<Self> {
        let location = self.slice_bytes(offset, size)?;
        // Direct values are lowered through one scalar register. Keep larger
        // implicit slices in a piece so capture retains every byte.
        if size > 8 && matches!(location, Self::ImplicitValue(_)) {
            Ok(Self::Pieces(vec![byte_piece(0, size, location)?]))
        } else {
            Ok(location)
        }
    }

    fn slice_bytes(&self, offset: u64, size: u64) -> Result<Self> {
        if size == 0
            && matches!(
                self,
                Self::RegisterValue { .. }
                    | Self::ComputedValue(_)
                    | Self::ImplicitValue(_)
                    | Self::AbsoluteAddressValue(_)
                    | Self::Pieces(_)
            )
        {
            return Ok(Self::ImplicitValue(Vec::new()));
        }
        let end = offset
            .checked_add(size)
            .ok_or_else(|| anyhow::anyhow!("aggregate byte range overflow"))?;
        match self {
            Self::Pieces(pieces) => {
                let mut selected = Vec::new();
                let mut cursor = offset;
                for piece in pieces {
                    anyhow::ensure!(
                        piece.bit_offset.is_multiple_of(8) && piece.bit_size.is_multiple_of(8),
                        "non-byte-aligned aggregate pieces are not supported"
                    );
                    let start = u64::from(piece.bit_offset / 8);
                    let piece_end = start + u64::from(piece.bit_size / 8);
                    let first = start.max(offset);
                    let last = piece_end.min(end);
                    if first >= last {
                        continue;
                    }
                    anyhow::ensure!(first >= cursor, "overlapping aggregate pieces");
                    if cursor < first {
                        selected.push(byte_piece(
                            cursor - offset,
                            first - cursor,
                            Self::OptimizedOut,
                        )?);
                    }
                    selected.push(byte_piece(
                        first - offset,
                        last - first,
                        piece.location.slice_bytes(first - start, last - first)?,
                    )?);
                    cursor = last;
                }
                if cursor < end {
                    selected.push(byte_piece(
                        cursor - offset,
                        end - cursor,
                        Self::OptimizedOut,
                    )?);
                }
                if selected.len() == 1 {
                    return Ok(*selected.remove(0).location);
                }
                Ok(Self::Pieces(selected))
            }
            Self::ImplicitValue(bytes) => {
                let first = usize::try_from(offset)?;
                let last = usize::try_from(end)?;
                Ok(bytes
                    .get(first..last)
                    .map(|bytes| Self::ImplicitValue(bytes.to_vec()))
                    .unwrap_or(Self::OptimizedOut))
            }
            Self::RegisterValue { dwarf_reg } => {
                slice_scalar(vec![PlanExprOp::LoadRegister(*dwarf_reg)], offset, size)
            }
            Self::ComputedValue(steps) => slice_scalar(steps.clone(), offset, size),
            // An address-valued scalar still needs relocation before slicing.
            Self::AbsoluteAddressValue(_) => {
                if offset == 0 && size == 8 {
                    Ok(self.clone())
                } else {
                    Err(PlanError::ValueBackedAggregateOffset {
                        offset: offset as i64,
                        location: self.clone(),
                    }
                    .into())
                }
            }
            _ => add_location_offset(self.clone(), i64::try_from(offset)?),
        }
    }
}

fn byte_piece(offset: u64, size: u64, location: VariableLocation) -> Result<PieceLocation> {
    Ok(PieceLocation {
        bit_offset: u32::try_from(
            offset
                .checked_mul(8)
                .ok_or_else(|| anyhow::anyhow!("piece offset overflow"))?,
        )?,
        bit_size: u32::try_from(
            size.checked_mul(8)
                .ok_or_else(|| anyhow::anyhow!("piece size overflow"))?,
        )?,
        location: Box::new(location),
    })
}

fn slice_scalar(mut steps: Vec<PlanExprOp>, offset: u64, size: u64) -> Result<VariableLocation> {
    anyhow::ensure!(
        size > 0 && offset.checked_add(size).is_some_and(|end| end <= 8),
        "aggregate slice exceeds the scalar register width"
    );
    if offset != 0 {
        steps.extend([
            PlanExprOp::PushConstant((offset * 8) as i64),
            PlanExprOp::Shr,
        ]);
    }
    if size < 8 {
        steps.extend([
            PlanExprOp::PushConstant(((1u64 << (size * 8)) - 1) as i64),
            PlanExprOp::And,
        ]);
    }
    Ok(VariableLocation::ComputedValue(steps))
}

impl VariableMaterializationPlan {
    /// Preserve the object layout while marking fields with missing bytes unavailable.
    pub fn composite_capture_type(&self) -> Result<TypeInfo> {
        let VariableMaterialization::Composite { pieces } = &self.materialization else {
            anyhow::bail!("expected a composite materialization");
        };
        let ty = self
            .dwarf_type
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("split variable has no DWARF type"))?;
        capture_type(pieces, ty, 0)
    }
}

fn capture_type(pieces: &[PlannedPiece], ty: &TypeInfo, offset: u64) -> Result<TypeInfo> {
    let mut output = ty.clone();
    match &mut output {
        TypeInfo::StructType { members, .. } | TypeInfo::UnionType { members, .. } => {
            for member in members {
                member.member_type = capture_type(
                    pieces,
                    &member.member_type,
                    offset
                        .checked_add(member.offset)
                        .ok_or_else(|| anyhow::anyhow!("member offset overflow"))?,
                )?;
                if matches!(
                    strip_type_aliases(&member.member_type),
                    TypeInfo::OptimizedOut { .. }
                ) {
                    member.bit_offset = None;
                    member.bit_size = None;
                }
            }
        }
        TypeInfo::TypedefType {
            underlying_type, ..
        }
        | TypeInfo::QualifiedType {
            underlying_type, ..
        } => {
            **underlying_type = capture_type(pieces, underlying_type, offset)?;
        }
        _ if has_missing_value_bytes(pieces, ty, offset)? => {
            return Ok(TypeInfo::OptimizedOut {
                name: ty.type_name(),
            });
        }
        _ => {}
    }
    Ok(output)
}

fn has_missing_value_bytes(pieces: &[PlannedPiece], ty: &TypeInfo, offset: u64) -> Result<bool> {
    if ty.size() == 0 || !has_missing_bytes(pieces, offset, ty.size())? {
        return Ok(false);
    }
    match strip_type_aliases(ty) {
        TypeInfo::StructType { members, .. } | TypeInfo::UnionType { members, .. } => {
            for member in members {
                let member_offset = offset
                    .checked_add(member.offset)
                    .ok_or_else(|| anyhow::anyhow!("member offset overflow"))?;
                if has_missing_value_bytes(pieces, &member.member_type, member_offset)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        TypeInfo::ArrayType {
            element_type,
            element_count,
            ..
        } if element_type.size() != 0 => {
            let stride = element_type.size();
            let count = element_count.unwrap_or(ty.size() / stride);
            for index in 0..count {
                let element_offset = index
                    .checked_mul(stride)
                    .and_then(|delta| offset.checked_add(delta))
                    .ok_or_else(|| anyhow::anyhow!("array element offset overflow"))?;
                if has_missing_value_bytes(pieces, element_type, element_offset)? {
                    return Ok(true);
                }
            }
            // Arrays share one element type, so retain it only when every
            // element's fields are readable. Missing padding is harmless.
            Ok(false)
        }
        _ => Ok(true),
    }
}

fn has_missing_bytes(pieces: &[PlannedPiece], offset: u64, size: u64) -> Result<bool> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| anyhow::anyhow!("field size overflow"))?;
    Ok(pieces.iter().any(|piece| {
        matches!(piece.source, PlannedPieceSource::Unavailable)
            && (piece.byte_offset as u64) < end
            && (piece.byte_offset + piece.byte_size) as u64 > offset
    }))
}
