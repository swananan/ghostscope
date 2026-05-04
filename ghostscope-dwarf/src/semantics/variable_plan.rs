//! Variable semantic plans before runtime-specific lowering.

use crate::core::{
    AddressExpr, Availability, ComputeStep, DieRef, HelperMode, InlineContextId, MemoryAccessSize,
    PieceLocation, Provenance, Result, RuntimeCapabilities, RuntimeRequirement, TypeId,
    UnsupportedReason, VariableId, VariableLocation, VerifierRisk,
};
use crate::semantics::PcRange;
use crate::TypeInfo;

/// Owned semantic view returned by PC-context variable queries.
#[derive(Debug, Clone, PartialEq)]
pub struct VisibleVariable {
    pub name: String,
    pub type_name: String,
    pub dwarf_type: Option<TypeInfo>,
    pub declaration: Option<DieRef>,
    pub type_id: Option<TypeId>,
    pub location: VariableLocation,
    pub availability: Availability,
    pub scope_depth: usize,
    pub is_parameter: bool,
    pub is_artificial: bool,
}

/// Diagnostic produced while answering a PC-sensitive variable query.
#[derive(Debug, Clone, PartialEq)]
pub struct VariableQueryDiagnostic {
    pub pc: u64,
    pub name: Option<String>,
    pub scope_depth: usize,
    pub availability: Availability,
    pub detail: String,
}

/// Visible variables plus non-fatal diagnostics from best-effort discovery.
#[derive(Debug, Clone, PartialEq)]
pub struct VisibleVariablesResult {
    pub variables: Vec<VisibleVariable>,
    pub diagnostics: Vec<VariableQueryDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VariableLoweringKind {
    DirectValue,
    UserMemoryRead,
    Composite,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableLoweringPlan {
    pub kind: VariableLoweringKind,
    pub availability: Availability,
    pub requirements: Vec<RuntimeRequirement>,
    pub helper_mode: HelperMode,
    pub required_registers: Vec<u16>,
    pub estimated_stack_bytes: usize,
    pub verifier_risk: VerifierRisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressOrigin {
    LinkTime,
    LinkTimeBase,
    RuntimeDerived,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PlannedAddress {
    pub kind: PlannedAddressKind,
    pub origin: AddressOrigin,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PlannedAddressKind {
    Constant { address: u64 },
    RegisterOffset { dwarf_reg: u16, offset: i64 },
    FrameBaseRelative { offset: i64 },
    Computed { steps: Vec<ComputeStep> },
}

#[derive(Debug, Clone, PartialEq)]
pub enum PlannedValue {
    Constant(i64),
    RegisterValue { dwarf_reg: u16 },
    ComputedValue { steps: Vec<ComputeStep> },
    ImplicitBytes(Vec<u8>),
    AddressValue { address: PlannedAddress },
}

#[derive(Debug, Clone, PartialEq)]
pub enum VariableMaterialization {
    DirectValue { value: PlannedValue },
    UserMemoryRead { address: PlannedAddress },
    Composite { pieces: Vec<PieceLocation> },
    Unavailable { availability: Availability },
}

#[derive(Debug, Clone, PartialEq)]
pub struct VariableMaterializationPlan {
    pub name: String,
    pub type_name: String,
    pub access_path: VariableAccessPath,
    pub dwarf_type: Option<TypeInfo>,
    pub availability: Availability,
    pub lowering: VariableLoweringPlan,
    pub materialization: VariableMaterialization,
}

/// Owned, PC-sensitive variable read plan before runtime-specific lowering.
#[derive(Debug, Clone, PartialEq)]
pub struct VariableReadPlan {
    pub name: String,
    pub type_name: String,
    pub access_path: VariableAccessPath,
    pub dwarf_type: Option<TypeInfo>,
    pub declaration: Option<DieRef>,
    pub type_id: Option<TypeId>,
    pub location: VariableLocation,
    pub availability: Availability,
    pub scope_depth: usize,
    pub is_parameter: bool,
    pub is_artificial: bool,
    pub pc_range: Option<PcRange>,
    pub inline_context: Option<InlineContextId>,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VariableAccessPath {
    pub segments: Vec<VariableAccessSegment>,
}

impl VariableAccessPath {
    pub fn new(segments: Vec<VariableAccessSegment>) -> Self {
        Self { segments }
    }

    pub fn fields(fields: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            segments: fields
                .into_iter()
                .map(|field| VariableAccessSegment::Field(field.into()))
                .collect(),
        }
    }

    fn suffix(&self) -> String {
        let mut suffix = String::new();
        for segment in &self.segments {
            match segment {
                VariableAccessSegment::Field(field) => {
                    suffix.push('.');
                    suffix.push_str(field);
                }
                VariableAccessSegment::ArrayIndex(index) => {
                    suffix.push('[');
                    suffix.push_str(&index.to_string());
                    suffix.push(']');
                }
                VariableAccessSegment::Dereference => suffix.push_str(".*"),
            }
        }
        suffix
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VariableAccessSegment {
    Field(String),
    ArrayIndex(i64),
    Dereference,
}

#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error("Variable '{name}' has no DWARF type information for access planning")]
    MissingTypeInfo { name: String },

    #[error("Unknown member '{field}' in {kind} '{type_name}' (known members: {members})")]
    UnknownMember {
        kind: &'static str,
        type_name: String,
        field: String,
        members: String,
    },

    #[error("array access requires array or pointer type, got '{type_name}'")]
    InvalidArrayAccess { type_name: String },

    #[error("pointer dereference requires pointer type, got '{type_name}'")]
    InvalidPointerDereference { type_name: String },

    #[error(
        "cannot apply byte offset {offset} to value-backed aggregate location {location:?}; field/array extraction from aggregate values is not implemented"
    )]
    ValueBackedAggregateOffset {
        offset: i64,
        location: VariableLocation,
    },

    #[error("cannot dereference variable location shape {location:?}")]
    UnsupportedDereference { location: VariableLocation },
}

impl PlanError {
    pub fn is_value_backed_aggregate_access(&self) -> bool {
        matches!(self, PlanError::ValueBackedAggregateOffset { .. })
    }
}

impl VariableReadPlan {
    pub fn from_visible_variable(variable: VisibleVariable, provenance: Provenance) -> Self {
        Self {
            name: variable.name,
            type_name: variable.type_name,
            access_path: VariableAccessPath::default(),
            dwarf_type: variable.dwarf_type,
            declaration: variable.declaration,
            type_id: variable.type_id,
            location: variable.location,
            availability: variable.availability,
            scope_depth: variable.scope_depth,
            is_parameter: variable.is_parameter,
            is_artificial: variable.is_artificial,
            pc_range: None,
            inline_context: None,
            provenance,
        }
    }

    pub fn bpf_lowering_plan(&self, capabilities: &RuntimeCapabilities) -> VariableLoweringPlan {
        if !self.availability.is_available() {
            return VariableLoweringPlan {
                kind: VariableLoweringKind::Unavailable,
                availability: self.availability.clone(),
                requirements: Vec::new(),
                helper_mode: HelperMode::NoUserMemoryRead,
                required_registers: Vec::new(),
                estimated_stack_bytes: 0,
                verifier_risk: VerifierRisk::Unsupported {
                    reason: "variable is unavailable".to_string(),
                },
            };
        }

        let kind = self.location.lowering_kind();
        let mut requirements = self.location.runtime_requirements();
        requirements.sort_by_key(requirement_rank);
        requirements.dedup();
        let mut required_registers = self.location.required_registers();
        required_registers.sort_unstable();
        required_registers.dedup();
        let estimated_stack_bytes = self.location.estimated_stack_bytes();
        let helper_mode = helper_mode_for_requirements(&requirements, capabilities);
        let verifier_risk =
            verifier_risk_for_requirements(&requirements, estimated_stack_bytes, capabilities);

        let availability = match &verifier_risk {
            VerifierRisk::StackBudgetExceeded { estimated, max } => {
                Availability::Unsupported(UnsupportedReason::ExpressionShape {
                    detail: format!(
                        "estimated BPF stack use {estimated} bytes exceeds capability limit {max}"
                    ),
                })
            }
            _ => requirements
                .iter()
                .find(|requirement| !capabilities.supports_requirement(requirement))
                .cloned()
                .map(Availability::Requires)
                .unwrap_or(Availability::Available),
        };

        VariableLoweringPlan {
            kind,
            availability,
            requirements,
            helper_mode,
            required_registers,
            estimated_stack_bytes,
            verifier_risk,
        }
    }

    pub fn materialization_plan(
        &self,
        capabilities: &RuntimeCapabilities,
    ) -> VariableMaterializationPlan {
        let lowering = self.bpf_lowering_plan(capabilities);
        let materialization = if !lowering.availability.is_available() {
            VariableMaterialization::Unavailable {
                availability: lowering.availability.clone(),
            }
        } else {
            match lowering.kind {
                VariableLoweringKind::DirectValue => {
                    match PlannedValue::from_location(self.location.clone()) {
                        Some(value) => VariableMaterialization::DirectValue { value },
                        None => VariableMaterialization::Unavailable {
                            availability: Availability::Unsupported(
                                UnsupportedReason::ExpressionShape {
                                    detail: format!(
                                        "location {} cannot be materialized as a direct value",
                                        self.location
                                    ),
                                },
                            ),
                        },
                    }
                }
                VariableLoweringKind::UserMemoryRead => {
                    match PlannedAddress::from_location(self.location.clone()) {
                        Some(address) => VariableMaterialization::UserMemoryRead { address },
                        None => VariableMaterialization::Unavailable {
                            availability: Availability::Unsupported(
                                UnsupportedReason::AddressClass {
                                    detail: format!(
                                        "location {} cannot be materialized as an address",
                                        self.location
                                    ),
                                },
                            ),
                        },
                    }
                }
                VariableLoweringKind::Composite => match &self.location {
                    VariableLocation::Pieces(pieces) => VariableMaterialization::Composite {
                        pieces: pieces.clone(),
                    },
                    _ => VariableMaterialization::Unavailable {
                        availability: Availability::Unsupported(
                            UnsupportedReason::ExpressionShape {
                                detail: "composite lowering without piece locations".to_string(),
                            },
                        ),
                    },
                },
                VariableLoweringKind::Unavailable => VariableMaterialization::Unavailable {
                    availability: lowering.availability.clone(),
                },
            }
        };

        VariableMaterializationPlan {
            name: self.name.clone(),
            type_name: self.type_name.clone(),
            access_path: self.access_path.clone(),
            dwarf_type: self.dwarf_type.clone(),
            availability: lowering.availability.clone(),
            lowering,
            materialization,
        }
    }

    pub fn plan_access_path(&self, path: &VariableAccessPath) -> Result<Self> {
        let mut plan = self.clone();
        for segment in &path.segments {
            plan = plan.plan_access_segment(segment)?;
        }

        plan.access_path.segments.extend(path.segments.clone());
        plan.name.push_str(&path.suffix());
        Ok(plan)
    }

    fn plan_access_segment(&self, segment: &VariableAccessSegment) -> Result<Self> {
        let dwarf_type = self
            .dwarf_type
            .clone()
            .ok_or_else(|| PlanError::MissingTypeInfo {
                name: self.name.clone(),
            })?;

        match segment {
            VariableAccessSegment::Field(field) => self.plan_field_access(&dwarf_type, field),
            VariableAccessSegment::ArrayIndex(index) => self.plan_array_index(&dwarf_type, *index),
            VariableAccessSegment::Dereference => self.plan_pointer_deref(&dwarf_type),
        }
    }

    fn plan_field_access(&self, dwarf_type: &TypeInfo, field: &str) -> Result<Self> {
        let (base_location, aggregate_type) = match strip_alias_type(dwarf_type) {
            TypeInfo::PointerType { target_type, .. } => (
                dereference_location(&self.location)?,
                strip_alias_type(target_type).clone(),
            ),
            ty => (self.location.clone(), ty.clone()),
        };

        let member = match strip_alias_type(&aggregate_type) {
            TypeInfo::StructType { name, members, .. } => members
                .iter()
                .find(|member| member.name == field)
                .cloned()
                .ok_or_else(|| unknown_member_error("struct", name, field, members))?,
            TypeInfo::UnionType { name, members, .. } => members
                .iter()
                .find(|member| member.name == field)
                .cloned()
                .ok_or_else(|| unknown_member_error("union", name, field, members))?,
            _ => {
                return Err(anyhow::anyhow!(
                    "member '{}' not found on type '{}'",
                    field,
                    aggregate_type.type_name()
                ));
            }
        };

        let mut plan = self.clone();
        plan.location = add_location_offset(base_location, member.offset as i64)?;
        plan.type_name = member.member_type.type_name();
        plan.dwarf_type = Some(member.member_type);
        plan.type_id = None;
        Ok(plan)
    }

    fn plan_array_index(&self, dwarf_type: &TypeInfo, index: i64) -> Result<Self> {
        let (base_location, element_type, stride) = match strip_alias_type(dwarf_type) {
            TypeInfo::ArrayType { element_type, .. } => {
                let stride = element_type.size().max(1);
                (self.location.clone(), element_type.as_ref().clone(), stride)
            }
            TypeInfo::PointerType { target_type, .. } => {
                let stride = target_type.size().max(1);
                (
                    dereference_location(&self.location)?,
                    target_type.as_ref().clone(),
                    stride,
                )
            }
            ty => {
                return Err(PlanError::InvalidArrayAccess {
                    type_name: ty.type_name(),
                }
                .into());
            }
        };

        let byte_offset = index.saturating_mul(stride as i64);
        let mut plan = self.clone();
        plan.location = add_location_offset(base_location, byte_offset)?;
        plan.type_name = element_type.type_name();
        plan.dwarf_type = Some(element_type);
        plan.type_id = None;
        Ok(plan)
    }

    fn plan_pointer_deref(&self, dwarf_type: &TypeInfo) -> Result<Self> {
        let target_type = match strip_alias_type(dwarf_type) {
            TypeInfo::PointerType { target_type, .. } => target_type.as_ref().clone(),
            ty => {
                return Err(PlanError::InvalidPointerDereference {
                    type_name: ty.type_name(),
                }
                .into());
            }
        };

        let mut plan = self.clone();
        plan.location = dereference_location(&self.location)?;
        plan.type_name = target_type.type_name();
        plan.dwarf_type = Some(target_type);
        plan.type_id = None;
        Ok(plan)
    }
}

impl PlannedValue {
    pub fn from_location(location: VariableLocation) -> Option<Self> {
        match location {
            VariableLocation::RegisterValue { dwarf_reg } => {
                Some(Self::RegisterValue { dwarf_reg })
            }
            VariableLocation::ComputedValue(steps) => {
                if let [ComputeStep::PushConstant(value)] = steps.as_slice() {
                    Some(Self::Constant(*value))
                } else {
                    Some(Self::ComputedValue { steps })
                }
            }
            VariableLocation::ImplicitValue(bytes) => Some(Self::ImplicitBytes(bytes)),
            VariableLocation::AbsoluteAddressValue(expr) => {
                PlannedAddress::from_location(VariableLocation::AbsoluteAddressValue(expr))
                    .map(|address| Self::AddressValue { address })
            }
            VariableLocation::Address(_)
            | VariableLocation::RegisterAddress { .. }
            | VariableLocation::FrameBaseRelative { .. }
            | VariableLocation::ComputedAddress(_)
            | VariableLocation::Pieces(_)
            | VariableLocation::OptimizedOut
            | VariableLocation::Unknown => None,
        }
    }
}

impl PlannedAddress {
    pub fn from_location(location: VariableLocation) -> Option<Self> {
        let (kind, origin) = match location {
            VariableLocation::Address(expr) | VariableLocation::AbsoluteAddressValue(expr) => {
                let origin = address_origin_for_steps(&expr.steps);
                (PlannedAddressKind::from_steps(expr.steps), origin)
            }
            VariableLocation::RegisterAddress { dwarf_reg, offset } => (
                PlannedAddressKind::RegisterOffset { dwarf_reg, offset },
                AddressOrigin::RuntimeDerived,
            ),
            VariableLocation::FrameBaseRelative { offset } => (
                PlannedAddressKind::FrameBaseRelative { offset },
                AddressOrigin::RuntimeDerived,
            ),
            VariableLocation::ComputedAddress(steps) => {
                let origin = address_origin_for_steps(&steps);
                (PlannedAddressKind::from_steps(steps), origin)
            }
            VariableLocation::RegisterValue { .. }
            | VariableLocation::ComputedValue(_)
            | VariableLocation::ImplicitValue(_)
            | VariableLocation::Pieces(_)
            | VariableLocation::OptimizedOut
            | VariableLocation::Unknown => return None,
        };

        Some(Self { kind, origin })
    }

    pub fn constant_link_time_address(&self) -> Option<u64> {
        match (&self.origin, &self.kind) {
            (AddressOrigin::LinkTime, PlannedAddressKind::Constant { address }) => Some(*address),
            (AddressOrigin::LinkTime, PlannedAddressKind::Computed { steps }) => {
                fold_constant_steps(steps)
            }
            _ => None,
        }
    }

    pub fn link_time_base_and_runtime_tail(&self) -> Option<(u64, &[ComputeStep])> {
        if self.origin != AddressOrigin::LinkTimeBase {
            return None;
        }

        match &self.kind {
            PlannedAddressKind::Computed { steps } => link_time_base_and_runtime_tail(steps),
            _ => None,
        }
    }
}

impl PlannedAddressKind {
    fn from_steps(steps: Vec<ComputeStep>) -> Self {
        match fold_constant_steps(&steps) {
            Some(address) => Self::Constant { address },
            None => Self::Computed { steps },
        }
    }
}

impl RuntimeCapabilities {
    pub fn supports_requirement(&self, requirement: &RuntimeRequirement) -> bool {
        match requirement {
            RuntimeRequirement::CallerFrame | RuntimeRequirement::DwarfCfiRecovery => {
                self.bounded_loops
            }
            RuntimeRequirement::SleepableUprobe => self.sleepable_uprobe,
            RuntimeRequirement::UserMemoryRead => {
                self.regular_uprobe || self.sleepable_uprobe || self.copy_from_user_task
            }
        }
    }
}

fn address_origin_for_steps(steps: &[ComputeStep]) -> AddressOrigin {
    if fold_constant_steps(steps).is_some() {
        return AddressOrigin::LinkTime;
    }

    if link_time_base_and_runtime_tail(steps).is_some() {
        return AddressOrigin::LinkTimeBase;
    }

    if steps_reference_runtime_state(steps) {
        AddressOrigin::RuntimeDerived
    } else {
        AddressOrigin::Unknown
    }
}

fn fold_constant_steps(steps: &[ComputeStep]) -> Option<u64> {
    let mut const_stack: Vec<i64> = Vec::new();
    for step in steps {
        match step {
            ComputeStep::PushConstant(value) => const_stack.push(*value),
            ComputeStep::Add => {
                let rhs = const_stack.pop()?;
                let lhs = const_stack.pop()?;
                const_stack.push(lhs.saturating_add(rhs));
            }
            _ => return None,
        }
    }

    if const_stack.len() == 1 && const_stack[0] >= 0 {
        Some(const_stack[0] as u64)
    } else {
        None
    }
}

fn link_time_base_and_runtime_tail(steps: &[ComputeStep]) -> Option<(u64, &[ComputeStep])> {
    let Some(ComputeStep::PushConstant(base)) = steps.first() else {
        return None;
    };

    if *base < 0 {
        return None;
    }

    for step in steps.iter().skip(1) {
        match step {
            ComputeStep::LoadRegister(_) => {
                break;
            }
            ComputeStep::Dereference { .. } => {
                return Some((*base as u64, &steps[1..]));
            }
            _ => {}
        }
    }

    None
}

fn steps_reference_runtime_state(steps: &[ComputeStep]) -> bool {
    steps.iter().any(|step| match step {
        ComputeStep::LoadRegister(_)
        | ComputeStep::Dereference { .. }
        | ComputeStep::EntryValueLookup { .. } => true,
        ComputeStep::If {
            then_branch,
            else_branch,
        } => {
            steps_reference_runtime_state(then_branch) || steps_reference_runtime_state(else_branch)
        }
        _ => false,
    })
}

trait VariableLocationLoweringExt {
    fn lowering_kind(&self) -> VariableLoweringKind;
    fn runtime_requirements(&self) -> Vec<RuntimeRequirement>;
    fn required_registers(&self) -> Vec<u16>;
    fn estimated_stack_bytes(&self) -> usize;
}

impl VariableLocationLoweringExt for VariableLocation {
    fn lowering_kind(&self) -> VariableLoweringKind {
        match self {
            VariableLocation::Address(_)
            | VariableLocation::RegisterAddress { .. }
            | VariableLocation::ComputedAddress(_)
            | VariableLocation::FrameBaseRelative { .. } => VariableLoweringKind::UserMemoryRead,
            VariableLocation::AbsoluteAddressValue(_)
            | VariableLocation::RegisterValue { .. }
            | VariableLocation::ComputedValue(_)
            | VariableLocation::ImplicitValue(_) => VariableLoweringKind::DirectValue,
            VariableLocation::Pieces(_) => VariableLoweringKind::Composite,
            VariableLocation::OptimizedOut | VariableLocation::Unknown => {
                VariableLoweringKind::Unavailable
            }
        }
    }

    fn runtime_requirements(&self) -> Vec<RuntimeRequirement> {
        match self {
            VariableLocation::Address(_)
            | VariableLocation::RegisterAddress { .. }
            | VariableLocation::ComputedAddress(_) => {
                let mut requirements = vec![RuntimeRequirement::UserMemoryRead];
                if let VariableLocation::ComputedAddress(steps) = self {
                    requirements.extend(requirements_for_steps(steps));
                }
                requirements
            }
            VariableLocation::FrameBaseRelative { .. } => vec![
                RuntimeRequirement::DwarfCfiRecovery,
                RuntimeRequirement::UserMemoryRead,
            ],
            VariableLocation::AbsoluteAddressValue(expr) => requirements_for_steps(&expr.steps),
            VariableLocation::ComputedValue(steps) => requirements_for_steps(steps),
            VariableLocation::Pieces(pieces) => pieces
                .iter()
                .flat_map(|piece| piece.location.runtime_requirements())
                .collect(),
            VariableLocation::RegisterValue { .. }
            | VariableLocation::ImplicitValue(_)
            | VariableLocation::OptimizedOut
            | VariableLocation::Unknown => Vec::new(),
        }
    }

    fn required_registers(&self) -> Vec<u16> {
        match self {
            VariableLocation::RegisterValue { dwarf_reg } => vec![*dwarf_reg],
            VariableLocation::RegisterAddress { dwarf_reg, .. } => vec![*dwarf_reg],
            VariableLocation::AbsoluteAddressValue(expr) => registers_for_steps(&expr.steps),
            VariableLocation::ComputedValue(steps) | VariableLocation::ComputedAddress(steps) => {
                registers_for_steps(steps)
            }
            VariableLocation::Pieces(pieces) => pieces
                .iter()
                .flat_map(|piece| piece.location.required_registers())
                .collect(),
            VariableLocation::Address(_)
            | VariableLocation::FrameBaseRelative { .. }
            | VariableLocation::ImplicitValue(_)
            | VariableLocation::OptimizedOut
            | VariableLocation::Unknown => Vec::new(),
        }
    }

    fn estimated_stack_bytes(&self) -> usize {
        match self {
            VariableLocation::AbsoluteAddressValue(expr) => {
                estimate_steps_stack_bytes(&expr.steps).max(8)
            }
            VariableLocation::ComputedValue(steps) | VariableLocation::ComputedAddress(steps) => {
                estimate_steps_stack_bytes(steps)
            }
            VariableLocation::Pieces(pieces) => pieces
                .iter()
                .map(|piece| piece.location.estimated_stack_bytes())
                .max()
                .unwrap_or(0),
            VariableLocation::Address(_)
            | VariableLocation::RegisterValue { .. }
            | VariableLocation::RegisterAddress { .. }
            | VariableLocation::FrameBaseRelative { .. } => 8,
            VariableLocation::ImplicitValue(bytes) => bytes.len(),
            VariableLocation::OptimizedOut | VariableLocation::Unknown => 0,
        }
    }
}

fn requirements_for_steps(steps: &[ComputeStep]) -> Vec<RuntimeRequirement> {
    let mut requirements = Vec::new();
    for step in steps {
        match step {
            ComputeStep::Dereference { .. } => {
                requirements.push(RuntimeRequirement::UserMemoryRead)
            }
            ComputeStep::EntryValueLookup {
                caller_pc_steps,
                cases,
            } => {
                requirements.push(RuntimeRequirement::CallerFrame);
                requirements.extend(requirements_for_steps(caller_pc_steps));
                for case in cases {
                    requirements.extend(requirements_for_steps(&case.value_steps));
                }
            }
            ComputeStep::If {
                then_branch,
                else_branch,
            } => {
                requirements.extend(requirements_for_steps(then_branch));
                requirements.extend(requirements_for_steps(else_branch));
            }
            _ => {}
        }
    }
    requirements
}

fn registers_for_steps(steps: &[ComputeStep]) -> Vec<u16> {
    let mut registers = Vec::new();
    collect_registers_for_steps(steps, &mut registers);
    registers
}

fn collect_registers_for_steps(steps: &[ComputeStep], registers: &mut Vec<u16>) {
    for step in steps {
        match step {
            ComputeStep::LoadRegister(register) => registers.push(*register),
            ComputeStep::EntryValueLookup {
                caller_pc_steps,
                cases,
            } => {
                collect_registers_for_steps(caller_pc_steps, registers);
                for case in cases {
                    collect_registers_for_steps(&case.value_steps, registers);
                }
            }
            ComputeStep::If {
                then_branch,
                else_branch,
            } => {
                collect_registers_for_steps(then_branch, registers);
                collect_registers_for_steps(else_branch, registers);
            }
            _ => {}
        }
    }
}

fn estimate_steps_stack_bytes(steps: &[ComputeStep]) -> usize {
    let nested = steps
        .iter()
        .map(|step| match step {
            ComputeStep::EntryValueLookup {
                caller_pc_steps,
                cases,
            } => cases
                .iter()
                .map(|case| estimate_steps_stack_bytes(&case.value_steps))
                .chain(std::iter::once(estimate_steps_stack_bytes(caller_pc_steps)))
                .max()
                .unwrap_or(0),
            ComputeStep::If {
                then_branch,
                else_branch,
            } => {
                estimate_steps_stack_bytes(then_branch).max(estimate_steps_stack_bytes(else_branch))
            }
            _ => 0,
        })
        .max()
        .unwrap_or(0);
    steps.len().saturating_mul(8).max(nested)
}

fn helper_mode_for_requirements(
    requirements: &[RuntimeRequirement],
    capabilities: &RuntimeCapabilities,
) -> HelperMode {
    if !requirements.contains(&RuntimeRequirement::UserMemoryRead) {
        HelperMode::NoUserMemoryRead
    } else if capabilities.sleepable_uprobe && capabilities.copy_from_user_task {
        HelperMode::CopyFromUserTask
    } else {
        HelperMode::ProbeReadUser
    }
}

fn verifier_risk_for_requirements(
    requirements: &[RuntimeRequirement],
    estimated_stack_bytes: usize,
    capabilities: &RuntimeCapabilities,
) -> VerifierRisk {
    if estimated_stack_bytes > capabilities.max_bpf_stack_bytes {
        return VerifierRisk::StackBudgetExceeded {
            estimated: estimated_stack_bytes,
            max: capabilities.max_bpf_stack_bytes,
        };
    }

    if requirements.iter().any(|requirement| {
        matches!(
            requirement,
            RuntimeRequirement::CallerFrame | RuntimeRequirement::DwarfCfiRecovery
        )
    }) {
        VerifierRisk::RequiresBoundedLoops
    } else {
        VerifierRisk::Low
    }
}

fn requirement_rank(requirement: &RuntimeRequirement) -> u8 {
    match requirement {
        RuntimeRequirement::CallerFrame => 0,
        RuntimeRequirement::SleepableUprobe => 1,
        RuntimeRequirement::UserMemoryRead => 2,
        RuntimeRequirement::DwarfCfiRecovery => 3,
    }
}

fn strip_alias_type(ty: &TypeInfo) -> &TypeInfo {
    match ty {
        TypeInfo::TypedefType {
            underlying_type, ..
        }
        | TypeInfo::QualifiedType {
            underlying_type, ..
        } => strip_alias_type(underlying_type),
        _ => ty,
    }
}

fn unknown_member_error(
    kind: &'static str,
    type_name: &str,
    field: &str,
    members: &[crate::StructMember],
) -> anyhow::Error {
    let mut member_names = members
        .iter()
        .map(|member| member.name.clone())
        .collect::<Vec<_>>();
    member_names.sort();
    member_names.dedup();
    let list = if member_names.is_empty() {
        "<none>".to_string()
    } else {
        member_names.join(", ")
    };
    PlanError::UnknownMember {
        kind,
        type_name: type_name.to_string(),
        field: field.to_string(),
        members: list,
    }
    .into()
}

/// Apply a byte offset to an address-backed source variable location.
pub fn add_location_offset(location: VariableLocation, offset: i64) -> Result<VariableLocation> {
    match location {
        VariableLocation::Address(expr) => {
            Ok(VariableLocation::Address(offset_address_expr(expr, offset)))
        }
        VariableLocation::RegisterAddress {
            dwarf_reg,
            offset: base,
        } => Ok(VariableLocation::RegisterAddress {
            dwarf_reg,
            offset: base.saturating_add(offset),
        }),
        VariableLocation::FrameBaseRelative { offset: base } => {
            Ok(VariableLocation::FrameBaseRelative {
                offset: base.saturating_add(offset),
            })
        }
        VariableLocation::ComputedAddress(mut steps) => {
            push_add_offset(&mut steps, offset);
            Ok(VariableLocation::ComputedAddress(steps))
        }
        VariableLocation::OptimizedOut => Ok(VariableLocation::OptimizedOut),
        VariableLocation::Unknown => Ok(VariableLocation::Unknown),
        VariableLocation::AbsoluteAddressValue(_)
        | VariableLocation::RegisterValue { .. }
        | VariableLocation::ComputedValue(_)
        | VariableLocation::ImplicitValue(_)
        | VariableLocation::Pieces(_) => {
            Err(PlanError::ValueBackedAggregateOffset { offset, location }.into())
        }
    }
}

fn offset_address_expr(mut expr: AddressExpr, offset: i64) -> AddressExpr {
    if let [ComputeStep::PushConstant(base)] = expr.steps.as_mut_slice() {
        *base = base.saturating_add(offset);
        return expr;
    }
    push_add_offset(&mut expr.steps, offset);
    expr
}

fn push_add_offset(steps: &mut Vec<ComputeStep>, offset: i64) {
    if offset != 0 {
        steps.push(ComputeStep::PushConstant(offset));
        steps.push(ComputeStep::Add);
    }
}

/// Turn a pointer-valued source variable location into its pointee location.
pub fn dereference_location(location: &VariableLocation) -> Result<VariableLocation> {
    match location {
        VariableLocation::AbsoluteAddressValue(expr) => Ok(VariableLocation::Address(expr.clone())),
        VariableLocation::RegisterValue { dwarf_reg } => {
            Ok(VariableLocation::ComputedAddress(vec![
                ComputeStep::LoadRegister(*dwarf_reg),
            ]))
        }
        VariableLocation::ComputedValue(steps) => {
            Ok(VariableLocation::ComputedAddress(steps.clone()))
        }
        VariableLocation::ImplicitValue(bytes) => {
            let mut address = 0u64;
            for (index, byte) in bytes.iter().take(8).enumerate() {
                address |= (*byte as u64) << (index * 8);
            }
            Ok(VariableLocation::Address(AddressExpr::constant(address)))
        }
        VariableLocation::Address(expr) => {
            let mut steps = expr.steps.clone();
            steps.push(ComputeStep::Dereference {
                size: MemoryAccessSize::U64,
            });
            Ok(VariableLocation::ComputedAddress(steps))
        }
        VariableLocation::RegisterAddress { dwarf_reg, offset } => {
            let mut steps = vec![ComputeStep::LoadRegister(*dwarf_reg)];
            push_add_offset(&mut steps, *offset);
            steps.push(ComputeStep::Dereference {
                size: MemoryAccessSize::U64,
            });
            Ok(VariableLocation::ComputedAddress(steps))
        }
        VariableLocation::ComputedAddress(steps) => {
            let mut steps = steps.clone();
            steps.push(ComputeStep::Dereference {
                size: MemoryAccessSize::U64,
            });
            Ok(VariableLocation::ComputedAddress(steps))
        }
        VariableLocation::OptimizedOut => Ok(VariableLocation::OptimizedOut),
        VariableLocation::Unknown => Ok(VariableLocation::Unknown),
        VariableLocation::FrameBaseRelative { .. } | VariableLocation::Pieces(_) => {
            Err(PlanError::UnsupportedDereference {
                location: location.clone(),
            }
            .into())
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VariablePlan {
    pub variable_id: VariableId,
    pub name: String,
    pub ty: TypeId,
    pub declaration: DieRef,
    pub pc_range: Option<PcRange>,
    pub inline_context: Option<InlineContextId>,
    pub location: VariableLocation,
    pub availability: Availability,
    pub provenance: Provenance,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{AddressExpr, EntryValueCase, MemoryAccessSize, TargetArch};
    use crate::StructMember;

    fn capabilities(regular_uprobe: bool) -> RuntimeCapabilities {
        RuntimeCapabilities {
            regular_uprobe,
            sleepable_uprobe: false,
            uprobe_multi: false,
            copy_from_user_task: false,
            max_bpf_stack_bytes: 512,
            bounded_loops: true,
            arch: TargetArch::X86_64,
        }
    }

    fn read_plan(location: VariableLocation) -> VariableReadPlan {
        VariableReadPlan {
            name: "value".to_string(),
            type_name: "int".to_string(),
            access_path: VariableAccessPath::default(),
            dwarf_type: None,
            declaration: None,
            type_id: None,
            location,
            availability: Availability::Available,
            scope_depth: 0,
            is_parameter: false,
            is_artificial: false,
            pc_range: None,
            inline_context: None,
            provenance: Provenance::DirectDie,
        }
    }

    fn typed_read_plan(location: VariableLocation, dwarf_type: TypeInfo) -> VariableReadPlan {
        VariableReadPlan {
            type_name: dwarf_type.type_name(),
            dwarf_type: Some(dwarf_type),
            ..read_plan(location)
        }
    }

    #[test]
    fn register_value_lowers_without_runtime_requirements() {
        let plan = read_plan(VariableLocation::RegisterValue { dwarf_reg: 0 });
        let lowering = plan.bpf_lowering_plan(&capabilities(false));

        assert_eq!(lowering.kind, VariableLoweringKind::DirectValue);
        assert_eq!(lowering.availability, Availability::Available);
        assert!(lowering.requirements.is_empty());
    }

    #[test]
    fn memory_location_requires_user_memory_read() {
        let plan = read_plan(VariableLocation::Address(AddressExpr::constant(0x1000)));
        let lowering = plan.bpf_lowering_plan(&capabilities(false));

        assert_eq!(lowering.kind, VariableLoweringKind::UserMemoryRead);
        assert_eq!(
            lowering.availability,
            Availability::Requires(RuntimeRequirement::UserMemoryRead)
        );
        assert_eq!(
            lowering.requirements,
            vec![RuntimeRequirement::UserMemoryRead]
        );
    }

    #[test]
    fn memory_location_is_available_with_regular_uprobe() {
        let plan = read_plan(VariableLocation::Address(AddressExpr::constant(0x1000)));
        let lowering = plan.bpf_lowering_plan(&capabilities(true));

        assert_eq!(lowering.kind, VariableLoweringKind::UserMemoryRead);
        assert_eq!(lowering.availability, Availability::Available);
        assert_eq!(lowering.helper_mode, HelperMode::ProbeReadUser);
        assert_eq!(lowering.verifier_risk, VerifierRisk::Low);
        assert!(lowering.required_registers.is_empty());
    }

    #[test]
    fn materialization_plan_preserves_link_time_address_origin() {
        let plan = read_plan(VariableLocation::Address(AddressExpr::constant(0x1000)));
        let materialized = plan.materialization_plan(&capabilities(true));

        match materialized.materialization {
            VariableMaterialization::UserMemoryRead { address } => {
                assert_eq!(address.origin, AddressOrigin::LinkTime);
                assert_eq!(address.constant_link_time_address(), Some(0x1000));
                assert_eq!(
                    address.kind,
                    PlannedAddressKind::Constant { address: 0x1000 }
                );
            }
            other => panic!("unexpected materialization: {other:?}"),
        }
    }

    #[test]
    fn materialization_plan_converts_register_address_to_address_kind() {
        let plan = read_plan(VariableLocation::RegisterAddress {
            dwarf_reg: 6,
            offset: -16,
        });
        let materialized = plan.materialization_plan(&capabilities(true));

        match materialized.materialization {
            VariableMaterialization::UserMemoryRead { address } => {
                assert_eq!(address.origin, AddressOrigin::RuntimeDerived);
                assert_eq!(
                    address.kind,
                    PlannedAddressKind::RegisterOffset {
                        dwarf_reg: 6,
                        offset: -16
                    }
                );
            }
            other => panic!("unexpected materialization: {other:?}"),
        }
    }

    #[test]
    fn materialization_plan_marks_static_base_before_deref() {
        let plan = read_plan(VariableLocation::ComputedAddress(vec![
            ComputeStep::PushConstant(0x3000),
            ComputeStep::Dereference {
                size: MemoryAccessSize::U64,
            },
            ComputeStep::PushConstant(16),
            ComputeStep::Add,
        ]));
        let materialized = plan.materialization_plan(&capabilities(true));

        match materialized.materialization {
            VariableMaterialization::UserMemoryRead { address } => {
                assert_eq!(address.origin, AddressOrigin::LinkTimeBase);
                let (base, tail) = address
                    .link_time_base_and_runtime_tail()
                    .expect("link-time base");
                assert_eq!(base, 0x3000);
                assert_eq!(tail.len(), 3);
            }
            other => panic!("unexpected materialization: {other:?}"),
        }
    }

    #[test]
    fn materialization_plan_preserves_arithmetic_before_first_deref() {
        let plan = read_plan(VariableLocation::ComputedAddress(vec![
            ComputeStep::PushConstant(0x3000),
            ComputeStep::PushConstant(8),
            ComputeStep::Add,
            ComputeStep::Dereference {
                size: MemoryAccessSize::U64,
            },
        ]));
        let materialized = plan.materialization_plan(&capabilities(true));

        match materialized.materialization {
            VariableMaterialization::UserMemoryRead { address } => {
                assert_eq!(address.origin, AddressOrigin::LinkTimeBase);
                let (base, tail) = address
                    .link_time_base_and_runtime_tail()
                    .expect("link-time base");
                assert_eq!(base, 0x3000);
                assert_eq!(
                    tail,
                    &[
                        ComputeStep::PushConstant(8),
                        ComputeStep::Add,
                        ComputeStep::Dereference {
                            size: MemoryAccessSize::U64,
                        },
                    ]
                );
            }
            other => panic!("unexpected materialization: {other:?}"),
        }
    }

    #[test]
    fn materialization_plan_keeps_absolute_address_value_direct() {
        let plan = read_plan(VariableLocation::AbsoluteAddressValue(
            AddressExpr::constant(0x2000),
        ));
        let materialized = plan.materialization_plan(&capabilities(false));

        match materialized.materialization {
            VariableMaterialization::DirectValue {
                value:
                    PlannedValue::AddressValue {
                        address:
                            PlannedAddress {
                                origin: AddressOrigin::LinkTime,
                                kind: PlannedAddressKind::Constant { address: 0x2000 },
                                ..
                            },
                    },
            } => {}
            VariableMaterialization::DirectValue { value } => {
                panic!("unexpected direct value: {value:?}");
            }
            other => panic!("unexpected materialization: {other:?}"),
        }
    }

    #[test]
    fn materialization_plan_converts_constant_direct_value() {
        let plan = read_plan(VariableLocation::ComputedValue(vec![
            ComputeStep::PushConstant(42),
        ]));
        let materialized = plan.materialization_plan(&capabilities(false));

        match materialized.materialization {
            VariableMaterialization::DirectValue {
                value: PlannedValue::Constant(42),
            } => {}
            other => panic!("unexpected materialization: {other:?}"),
        }
    }

    #[test]
    fn materialization_plan_converts_register_direct_value() {
        let plan = read_plan(VariableLocation::RegisterValue { dwarf_reg: 6 });
        let materialized = plan.materialization_plan(&capabilities(false));

        match materialized.materialization {
            VariableMaterialization::DirectValue {
                value: PlannedValue::RegisterValue { dwarf_reg: 6 },
            } => {}
            other => panic!("unexpected materialization: {other:?}"),
        }
    }

    #[test]
    fn materialization_plan_surfaces_piece_locations_without_first_piece_fallback() {
        let plan = read_plan(VariableLocation::Pieces(vec![PieceLocation {
            bit_offset: 0,
            bit_size: 32,
            location: Box::new(VariableLocation::RegisterValue { dwarf_reg: 0 }),
        }]));
        let materialized = plan.materialization_plan(&capabilities(true));

        match materialized.materialization {
            VariableMaterialization::Composite { pieces } => {
                assert_eq!(pieces.len(), 1);
            }
            other => panic!("unexpected materialization: {other:?}"),
        }
    }

    #[test]
    fn absolute_address_value_lowers_without_user_memory_read() {
        let plan = read_plan(VariableLocation::AbsoluteAddressValue(
            AddressExpr::constant(0x1000),
        ));
        let lowering = plan.bpf_lowering_plan(&capabilities(false));

        assert_eq!(lowering.kind, VariableLoweringKind::DirectValue);
        assert_eq!(lowering.availability, Availability::Available);
        assert!(lowering.requirements.is_empty());
    }

    #[test]
    fn memory_location_prefers_copy_from_user_task_when_available() {
        let mut capabilities = capabilities(false);
        capabilities.sleepable_uprobe = true;
        capabilities.copy_from_user_task = true;
        let plan = read_plan(VariableLocation::Address(AddressExpr::constant(0x1000)));
        let lowering = plan.bpf_lowering_plan(&capabilities);

        assert_eq!(lowering.availability, Availability::Available);
        assert_eq!(lowering.helper_mode, HelperMode::CopyFromUserTask);
    }

    #[test]
    fn register_address_records_required_register() {
        let plan = read_plan(VariableLocation::RegisterAddress {
            dwarf_reg: 6,
            offset: -16,
        });
        let lowering = plan.bpf_lowering_plan(&capabilities(true));

        assert_eq!(lowering.required_registers, vec![6]);
        assert_eq!(lowering.estimated_stack_bytes, 8);
    }

    #[test]
    fn entry_value_steps_surface_caller_frame_and_memory_requirements() {
        let plan = read_plan(VariableLocation::ComputedValue(vec![
            ComputeStep::EntryValueLookup {
                caller_pc_steps: vec![
                    ComputeStep::LoadRegister(7),
                    ComputeStep::Dereference {
                        size: MemoryAccessSize::U64,
                    },
                ],
                cases: vec![EntryValueCase {
                    caller_return_pc: 0x10,
                    value_steps: vec![ComputeStep::LoadRegister(5)],
                }],
            },
        ]));
        let lowering = plan.bpf_lowering_plan(&capabilities(true));

        assert_eq!(lowering.availability, Availability::Available);
        assert_eq!(
            lowering.requirements,
            vec![
                RuntimeRequirement::CallerFrame,
                RuntimeRequirement::UserMemoryRead
            ]
        );
        assert_eq!(lowering.required_registers, vec![5, 7]);
        assert_eq!(lowering.verifier_risk, VerifierRisk::RequiresBoundedLoops);
    }

    #[test]
    fn stack_budget_excess_reports_unsupported_availability() {
        let mut capabilities = capabilities(true);
        capabilities.max_bpf_stack_bytes = 16;
        let plan = read_plan(VariableLocation::ComputedValue(vec![
            ComputeStep::PushConstant(1);
            8
        ]));
        let lowering = plan.bpf_lowering_plan(&capabilities);

        assert!(matches!(
            lowering.availability,
            Availability::Unsupported(UnsupportedReason::ExpressionShape { .. })
        ));
        assert_eq!(
            lowering.verifier_risk,
            VerifierRisk::StackBudgetExceeded {
                estimated: 64,
                max: 16,
            }
        );
    }

    #[test]
    fn field_access_adds_member_offset_and_type() {
        let int_type = TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        };
        let plan = typed_read_plan(
            VariableLocation::RegisterAddress {
                dwarf_reg: 6,
                offset: -32,
            },
            TypeInfo::StructType {
                name: "Request".to_string(),
                size: 16,
                members: vec![StructMember {
                    name: "fd".to_string(),
                    member_type: int_type.clone(),
                    offset: 12,
                    bit_offset: None,
                    bit_size: None,
                }],
            },
        );

        let access = VariableAccessPath::fields(["fd"]);
        let planned = plan.plan_access_path(&access).expect("field access");

        assert_eq!(planned.name, "value.fd");
        assert_eq!(planned.access_path, access);
        assert_eq!(planned.dwarf_type, Some(int_type));
        assert_eq!(
            planned.location,
            VariableLocation::RegisterAddress {
                dwarf_reg: 6,
                offset: -20,
            }
        );
        assert_eq!(
            planned
                .materialization_plan(&capabilities(true))
                .access_path
                .segments,
            vec![VariableAccessSegment::Field("fd".to_string())]
        );
    }

    #[test]
    fn field_access_unknown_member_reports_known_members() {
        let int_type = TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        };
        let plan = typed_read_plan(
            VariableLocation::Address(AddressExpr::constant(0x1000)),
            TypeInfo::StructType {
                name: "Request".to_string(),
                size: 8,
                members: vec![
                    StructMember {
                        name: "fd".to_string(),
                        member_type: int_type.clone(),
                        offset: 0,
                        bit_offset: None,
                        bit_size: None,
                    },
                    StructMember {
                        name: "flags".to_string(),
                        member_type: int_type,
                        offset: 4,
                        bit_offset: None,
                        bit_size: None,
                    },
                ],
            },
        );

        let err = plan
            .plan_access_path(&VariableAccessPath::fields(["missing"]))
            .expect_err("unknown member should fail");

        assert_eq!(
            err.to_string(),
            "Unknown member 'missing' in struct 'Request' (known members: fd, flags)"
        );
    }

    #[test]
    fn field_access_folds_constant_address_offsets() {
        let int_type = TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        };
        let plan = typed_read_plan(
            VariableLocation::Address(AddressExpr::constant(0x1000)),
            TypeInfo::StructType {
                name: "Request".to_string(),
                size: 16,
                members: vec![StructMember {
                    name: "fd".to_string(),
                    member_type: int_type,
                    offset: 12,
                    bit_offset: None,
                    bit_size: None,
                }],
            },
        );

        let planned = plan
            .plan_access_path(&VariableAccessPath::fields(["fd"]))
            .expect("field access");

        assert_eq!(
            planned.location,
            VariableLocation::Address(AddressExpr::constant(0x100c))
        );
    }

    #[test]
    fn field_access_rejects_value_backed_aggregates() {
        let int_type = TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        };
        let struct_type = TypeInfo::StructType {
            name: "Pair".to_string(),
            size: 8,
            members: vec![StructMember {
                name: "b".to_string(),
                member_type: int_type,
                offset: 4,
                bit_offset: None,
                bit_size: None,
            }],
        };
        let access = VariableAccessPath::fields(["b"]);

        for location in [
            VariableLocation::AbsoluteAddressValue(AddressExpr::constant(0x1000)),
            VariableLocation::RegisterValue { dwarf_reg: 0 },
            VariableLocation::ComputedValue(vec![ComputeStep::LoadRegister(0)]),
        ] {
            let plan = typed_read_plan(location, struct_type.clone());
            let err = plan
                .plan_access_path(&access)
                .expect_err("value-backed aggregate field access should fail");
            assert!(
                err.downcast_ref::<PlanError>()
                    .is_some_and(PlanError::is_value_backed_aggregate_access),
                "unexpected error: {err}"
            );
        }
    }

    #[test]
    fn array_index_rejects_value_backed_aggregates() {
        let int_type = TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        };
        let array_type = TypeInfo::ArrayType {
            element_type: Box::new(int_type),
            element_count: Some(2),
            total_size: Some(8),
        };
        let access = VariableAccessPath::new(vec![VariableAccessSegment::ArrayIndex(1)]);

        for location in [
            VariableLocation::AbsoluteAddressValue(AddressExpr::constant(0x1000)),
            VariableLocation::RegisterValue { dwarf_reg: 0 },
            VariableLocation::ComputedValue(vec![ComputeStep::LoadRegister(0)]),
        ] {
            let plan = typed_read_plan(location, array_type.clone());
            let err = plan
                .plan_access_path(&access)
                .expect_err("value-backed aggregate array access should fail");
            assert!(
                err.downcast_ref::<PlanError>()
                    .is_some_and(PlanError::is_value_backed_aggregate_access),
                "unexpected error: {err}"
            );
        }
    }

    #[test]
    fn pointer_field_access_dereferences_then_offsets() {
        let int_type = TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        };
        let struct_type = TypeInfo::StructType {
            name: "Node".to_string(),
            size: 16,
            members: vec![StructMember {
                name: "value".to_string(),
                member_type: int_type,
                offset: 8,
                bit_offset: None,
                bit_size: None,
            }],
        };
        let plan = typed_read_plan(
            VariableLocation::RegisterValue { dwarf_reg: 5 },
            TypeInfo::PointerType {
                target_type: Box::new(struct_type),
                size: 8,
            },
        );

        let access = VariableAccessPath::fields(["value"]);
        let planned = plan.plan_access_path(&access).expect("pointer field");

        assert_eq!(
            planned.location,
            VariableLocation::ComputedAddress(vec![
                ComputeStep::LoadRegister(5),
                ComputeStep::PushConstant(8),
                ComputeStep::Add,
            ])
        );
    }

    #[test]
    fn pointer_field_access_from_absolute_address_value_rebases_memory_location() {
        let int_type = TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        };
        let struct_type = TypeInfo::StructType {
            name: "Node".to_string(),
            size: 16,
            members: vec![StructMember {
                name: "value".to_string(),
                member_type: int_type,
                offset: 8,
                bit_offset: None,
                bit_size: None,
            }],
        };
        let plan = typed_read_plan(
            VariableLocation::AbsoluteAddressValue(AddressExpr::constant(0x1000)),
            TypeInfo::PointerType {
                target_type: Box::new(struct_type),
                size: 8,
            },
        );

        let planned = plan
            .plan_access_path(&VariableAccessPath::fields(["value"]))
            .expect("pointer field");

        assert_eq!(
            planned.location,
            VariableLocation::Address(AddressExpr::constant(0x1008))
        );
    }

    #[test]
    fn pointer_field_access_from_computed_value_uses_value_as_address() {
        let int_type = TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        };
        let struct_type = TypeInfo::StructType {
            name: "Node".to_string(),
            size: 16,
            members: vec![StructMember {
                name: "value".to_string(),
                member_type: int_type,
                offset: 8,
                bit_offset: None,
                bit_size: None,
            }],
        };
        let plan = typed_read_plan(
            VariableLocation::ComputedValue(vec![ComputeStep::PushConstant(0x2000)]),
            TypeInfo::PointerType {
                target_type: Box::new(struct_type),
                size: 8,
            },
        );

        let planned = plan
            .plan_access_path(&VariableAccessPath::fields(["value"]))
            .expect("pointer field");

        assert_eq!(
            planned.location,
            VariableLocation::ComputedAddress(vec![
                ComputeStep::PushConstant(0x2000),
                ComputeStep::PushConstant(8),
                ComputeStep::Add,
            ])
        );
    }

    #[test]
    fn array_index_access_uses_element_stride() {
        let int_type = TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        };
        let plan = typed_read_plan(
            VariableLocation::Address(AddressExpr::constant(0x1000)),
            TypeInfo::ArrayType {
                element_type: Box::new(int_type),
                element_count: Some(8),
                total_size: Some(32),
            },
        );

        let access = VariableAccessPath::new(vec![VariableAccessSegment::ArrayIndex(3)]);
        let planned = plan.plan_access_path(&access).expect("array index");

        assert_eq!(planned.name, "value[3]");
        assert_eq!(
            planned.location,
            VariableLocation::Address(AddressExpr::constant(0x100c))
        );
    }
}
