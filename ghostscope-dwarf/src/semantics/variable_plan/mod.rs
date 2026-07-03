//! Variable semantic plans before runtime-specific lowering.

use crate::core::{
    AddressExpr, Availability, DieRef, HelperMode, InlineContextId, MemoryAccessSize,
    PieceLocation, PlanExprOp, Provenance, Result, RuntimeCapabilities, RuntimeRequirement, TypeId,
    UnsupportedReason, VariableId, VariableLocation, VerifierRisk,
};
use crate::semantics::{
    indexable_element_layout, member_layout, strip_type_aliases, PcRange, TypeLayoutError,
};
use crate::TypeInfo;
use std::path::PathBuf;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeComputedKind {
    Address,
    Value,
}

/// Runtime expression selected by DWARF semantic planning.
///
/// This is intentionally still expressive enough to carry the DWARF evaluator's
/// stack program, but it is no longer a bare location/value result. The planner
/// classifies the expression as an address or a value before compiler lowering.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeComputedExpr {
    kind: RuntimeComputedKind,
    ops: Vec<PlanExprOp>,
}

impl RuntimeComputedExpr {
    pub(crate) fn address(ops: Vec<PlanExprOp>) -> Self {
        Self {
            kind: RuntimeComputedKind::Address,
            ops,
        }
    }

    pub(crate) fn value(ops: Vec<PlanExprOp>) -> Self {
        Self {
            kind: RuntimeComputedKind::Value,
            ops,
        }
    }

    pub fn ops(&self) -> &[PlanExprOp] {
        &self.ops
    }

    pub fn kind(&self) -> RuntimeComputedKind {
        self.kind
    }

    pub fn runtime_requirements(&self) -> Vec<RuntimeRequirement> {
        requirements_for_steps(&self.ops)
    }

    pub fn required_registers(&self) -> Vec<u16> {
        registers_for_steps(&self.ops)
    }

    pub fn estimated_stack_bytes(&self) -> usize {
        estimate_steps_stack_bytes(&self.ops)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PlannedAddressKind {
    Constant { address: u64 },
    RegisterOffset { dwarf_reg: u16, offset: i64 },
    FrameBaseRelative { offset: i64 },
    RuntimeComputed { expr: RuntimeComputedExpr },
}

#[derive(Debug, Clone, PartialEq)]
pub enum PlannedValue {
    Constant {
        value: i64,
        size: MemoryAccessSize,
    },
    RegisterValue {
        dwarf_reg: u16,
        size: MemoryAccessSize,
    },
    RuntimeComputed {
        expr: RuntimeComputedExpr,
        result_size: MemoryAccessSize,
    },
    ImplicitBytes(Vec<u8>),
    AddressValue {
        address: PlannedAddress,
        size: MemoryAccessSize,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum VariableMaterialization {
    DirectValue { value: PlannedValue },
    UserMemoryRead { address: PlannedAddress },
    Composite { pieces: Vec<PieceLocation> },
    Unavailable { availability: Availability },
}

#[derive(Debug, Clone, PartialEq)]
pub enum LvalueAddressPlan {
    Address { address: PlannedAddress },
    Unavailable { availability: Availability },
}

#[derive(Debug, Clone, PartialEq)]
pub struct VariableMaterializationPlan {
    pub name: String,
    pub type_name: String,
    pub access_path: VariableAccessPath,
    pub module_path: Option<PathBuf>,
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
    pub module_path: Option<PathBuf>,
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

    #[error("Pointer arithmetic requires a pointer or array expression, got '{type_name}'")]
    InvalidPointerArithmetic { type_name: String },

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ElementIndexContext {
    AccessPath,
    PointerArithmetic,
}

impl VariableReadPlan {
    pub fn from_visible_variable(variable: VisibleVariable, provenance: Provenance) -> Self {
        Self {
            name: variable.name,
            type_name: variable.type_name,
            access_path: VariableAccessPath::default(),
            module_path: None,
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
                    let size = planned_value_size(self.dwarf_type.as_ref());
                    match PlannedValue::from_location(self.location.clone(), size) {
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
            module_path: self.module_path.clone(),
            dwarf_type: self.dwarf_type.clone(),
            availability: lowering.availability.clone(),
            lowering,
            materialization,
        }
    }

    pub fn lvalue_address_plan(&self) -> LvalueAddressPlan {
        if !self.availability.is_available() {
            LvalueAddressPlan::Unavailable {
                availability: self.availability.clone(),
            }
        } else {
            lvalue_address_materialization(&self.name, &self.location)
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

    /// Plan pointer-style element access for expressions like `ptr +/- K`.
    ///
    /// This keeps pointer dereference and element-size scaling in the DWARF
    /// semantic layer instead of making compiler lowering rewrite locations.
    pub fn plan_pointer_element_index(&self, index: i64) -> Result<Self> {
        let dwarf_type = self
            .dwarf_type
            .clone()
            .ok_or_else(|| PlanError::MissingTypeInfo {
                name: self.name.clone(),
            })?;
        let mut plan =
            self.plan_element_index(&dwarf_type, index, ElementIndexContext::PointerArithmetic)?;
        let segment = VariableAccessSegment::ArrayIndex(index);
        plan.access_path.segments.push(segment.clone());
        plan.name
            .push_str(&VariableAccessPath::new(vec![segment]).suffix());
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
        let (base_location, aggregate_type) = match strip_type_aliases(dwarf_type) {
            TypeInfo::PointerType { target_type, .. } => (
                dereference_location(&self.location)?,
                strip_type_aliases(target_type).clone(),
            ),
            ty => (self.location.clone(), ty.clone()),
        };

        let member = member_layout(&aggregate_type, field).map_err(|err| match err {
            TypeLayoutError::UnknownMember {
                kind,
                type_name,
                field,
                members,
            } => PlanError::UnknownMember {
                kind,
                type_name,
                field,
                members,
            }
            .into(),
            TypeLayoutError::InvalidMemberBase { type_name } => {
                anyhow::anyhow!("member '{field}' not found on type '{type_name}'")
            }
        })?;

        let mut plan = self.clone();
        plan.location = add_location_offset(base_location, member.offset as i64)?;
        plan.type_name = member.member_type.type_name();
        plan.dwarf_type = Some(member.member_type);
        plan.type_id = None;
        Ok(plan)
    }

    fn plan_array_index(&self, dwarf_type: &TypeInfo, index: i64) -> Result<Self> {
        self.plan_element_index(dwarf_type, index, ElementIndexContext::AccessPath)
    }

    fn plan_element_index(
        &self,
        dwarf_type: &TypeInfo,
        index: i64,
        context: ElementIndexContext,
    ) -> Result<Self> {
        let base_location = match strip_type_aliases(dwarf_type) {
            TypeInfo::ArrayType { .. } => self.location.clone(),
            TypeInfo::PointerType { .. } => dereference_location(&self.location)?,
            ty => {
                let type_name = ty.type_name();
                return Err(match context {
                    ElementIndexContext::AccessPath => PlanError::InvalidArrayAccess { type_name },
                    ElementIndexContext::PointerArithmetic => {
                        PlanError::InvalidPointerArithmetic { type_name }
                    }
                }
                .into());
            }
        };
        let layout = indexable_element_layout(dwarf_type)
            .expect("array and pointer types must have element layout");

        let byte_offset = index.saturating_mul(layout.stride as i64);
        let mut plan = self.clone();
        plan.location = add_location_offset(base_location, byte_offset)?;
        plan.type_name = layout.element_type.type_name();
        plan.dwarf_type = Some(layout.element_type);
        plan.type_id = None;
        Ok(plan)
    }

    fn plan_pointer_deref(&self, dwarf_type: &TypeInfo) -> Result<Self> {
        let target_type = match strip_type_aliases(dwarf_type) {
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
    pub fn from_location(location: VariableLocation, size: MemoryAccessSize) -> Option<Self> {
        match location {
            VariableLocation::RegisterValue { dwarf_reg } => {
                Some(Self::RegisterValue { dwarf_reg, size })
            }
            VariableLocation::ComputedValue(steps) => {
                if let [PlanExprOp::PushConstant(value)] = steps.as_slice() {
                    Some(Self::Constant {
                        value: *value,
                        size,
                    })
                } else {
                    Some(Self::RuntimeComputed {
                        expr: RuntimeComputedExpr::value(steps),
                        result_size: size,
                    })
                }
            }
            VariableLocation::ImplicitValue(bytes) => Some(Self::ImplicitBytes(bytes)),
            VariableLocation::AbsoluteAddressValue(expr) => {
                PlannedAddress::from_location(VariableLocation::AbsoluteAddressValue(expr))
                    .map(|address| Self::AddressValue { address, size })
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
            (AddressOrigin::LinkTime, PlannedAddressKind::RuntimeComputed { expr }) => {
                fold_constant_steps(expr.ops())
            }
            _ => None,
        }
    }

    pub fn link_time_base_and_runtime_tail(&self) -> Option<(u64, &[PlanExprOp])> {
        if self.origin != AddressOrigin::LinkTimeBase {
            return None;
        }

        match &self.kind {
            PlannedAddressKind::RuntimeComputed { expr } => {
                link_time_base_and_runtime_tail(expr.ops())
            }
            _ => None,
        }
    }
}

impl PlannedAddressKind {
    fn from_steps(steps: Vec<PlanExprOp>) -> Self {
        match fold_constant_steps(&steps) {
            Some(address) => Self::Constant { address },
            None => Self::RuntimeComputed {
                expr: RuntimeComputedExpr::address(steps),
            },
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

fn planned_value_size(dwarf_type: Option<&TypeInfo>) -> MemoryAccessSize {
    dwarf_type
        .map(|ty| MemoryAccessSize::from_size(ty.size()))
        .unwrap_or(MemoryAccessSize::U64)
}

fn lvalue_address_materialization(name: &str, location: &VariableLocation) -> LvalueAddressPlan {
    match location {
        VariableLocation::Address(_)
        | VariableLocation::RegisterAddress { .. }
        | VariableLocation::FrameBaseRelative { .. }
        | VariableLocation::ComputedAddress(_) => {
            match PlannedAddress::from_location(location.clone()) {
                Some(address) => LvalueAddressPlan::Address { address },
                None => LvalueAddressPlan::Unavailable {
                    availability: Availability::Unsupported(UnsupportedReason::AddressClass {
                        detail: format!(
                            "DWARF variable '{name}' has an address-backed location that could not be planned"
                        ),
                    }),
                },
            }
        }
        VariableLocation::OptimizedOut => LvalueAddressPlan::Unavailable {
            availability: Availability::OptimizedOut,
        },
        VariableLocation::Pieces(_) => LvalueAddressPlan::Unavailable {
            availability: Availability::Unsupported(UnsupportedReason::ExpressionShape {
                detail: "split variable pieces cannot be materialized as one lvalue address"
                    .to_string(),
            }),
        },
        VariableLocation::AbsoluteAddressValue(_)
        | VariableLocation::RegisterValue { .. }
        | VariableLocation::ComputedValue(_)
        | VariableLocation::ImplicitValue(_) => LvalueAddressPlan::Unavailable {
            availability: Availability::Unsupported(UnsupportedReason::AddressClass {
                detail: "cannot take address of value-backed DWARF expression".to_string(),
            }),
        },
        VariableLocation::Unknown => LvalueAddressPlan::Unavailable {
            availability: Availability::Unsupported(UnsupportedReason::AddressClass {
                detail: "unknown DWARF variable location".to_string(),
            }),
        },
    }
}

fn address_origin_for_steps(steps: &[PlanExprOp]) -> AddressOrigin {
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

fn fold_constant_steps(steps: &[PlanExprOp]) -> Option<u64> {
    let mut const_stack: Vec<i64> = Vec::new();
    for step in steps {
        match step {
            PlanExprOp::PushConstant(value) => const_stack.push(*value),
            PlanExprOp::Add => {
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

fn link_time_base_and_runtime_tail(steps: &[PlanExprOp]) -> Option<(u64, &[PlanExprOp])> {
    let Some(PlanExprOp::PushConstant(base)) = steps.first() else {
        return None;
    };

    if *base < 0 {
        return None;
    }

    for step in steps.iter().skip(1) {
        match step {
            PlanExprOp::LoadRegister(_) => {
                break;
            }
            PlanExprOp::FormTlsAddress => return None,
            PlanExprOp::Dereference { .. } => {
                return Some((*base as u64, &steps[1..]));
            }
            _ => {}
        }
    }

    None
}

fn steps_reference_runtime_state(steps: &[PlanExprOp]) -> bool {
    steps.iter().any(|step| match step {
        PlanExprOp::LoadRegister(_)
        | PlanExprOp::Dereference { .. }
        | PlanExprOp::FormTlsAddress
        | PlanExprOp::EntryValueLookup { .. } => true,
        PlanExprOp::If {
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

fn requirements_for_steps(steps: &[PlanExprOp]) -> Vec<RuntimeRequirement> {
    let mut requirements = Vec::new();
    for step in steps {
        match step {
            PlanExprOp::Dereference { .. } => requirements.push(RuntimeRequirement::UserMemoryRead),
            PlanExprOp::EntryValueLookup {
                caller_pc_steps,
                cases,
            } => {
                requirements.push(RuntimeRequirement::CallerFrame);
                requirements.extend(requirements_for_steps(caller_pc_steps));
                for case in cases {
                    requirements.extend(requirements_for_steps(&case.value_steps));
                }
            }
            PlanExprOp::If {
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

fn registers_for_steps(steps: &[PlanExprOp]) -> Vec<u16> {
    let mut registers = Vec::new();
    collect_registers_for_steps(steps, &mut registers);
    registers
}

fn collect_registers_for_steps(steps: &[PlanExprOp], registers: &mut Vec<u16>) {
    for step in steps {
        match step {
            PlanExprOp::LoadRegister(register) => registers.push(*register),
            PlanExprOp::EntryValueLookup {
                caller_pc_steps,
                cases,
            } => {
                collect_registers_for_steps(caller_pc_steps, registers);
                for case in cases {
                    collect_registers_for_steps(&case.value_steps, registers);
                }
            }
            PlanExprOp::If {
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

fn estimate_steps_stack_bytes(steps: &[PlanExprOp]) -> usize {
    let nested = steps
        .iter()
        .map(|step| match step {
            PlanExprOp::EntryValueLookup {
                caller_pc_steps,
                cases,
            } => cases
                .iter()
                .map(|case| estimate_steps_stack_bytes(&case.value_steps))
                .chain(std::iter::once(estimate_steps_stack_bytes(caller_pc_steps)))
                .max()
                .unwrap_or(0),
            PlanExprOp::If {
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
    if let [PlanExprOp::PushConstant(base)] = expr.steps.as_mut_slice() {
        *base = base.saturating_add(offset);
        return expr;
    }
    push_add_offset(&mut expr.steps, offset);
    expr
}

fn push_add_offset(steps: &mut Vec<PlanExprOp>, offset: i64) {
    if offset != 0 {
        steps.push(PlanExprOp::PushConstant(offset));
        steps.push(PlanExprOp::Add);
    }
}

/// Turn a pointer-valued source variable location into its pointee location.
pub fn dereference_location(location: &VariableLocation) -> Result<VariableLocation> {
    match location {
        VariableLocation::AbsoluteAddressValue(expr) => Ok(VariableLocation::Address(expr.clone())),
        VariableLocation::RegisterValue { dwarf_reg } => {
            Ok(VariableLocation::ComputedAddress(vec![
                PlanExprOp::LoadRegister(*dwarf_reg),
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
            steps.push(PlanExprOp::Dereference {
                size: MemoryAccessSize::U64,
            });
            Ok(VariableLocation::ComputedAddress(steps))
        }
        VariableLocation::RegisterAddress { dwarf_reg, offset } => {
            let mut steps = vec![PlanExprOp::LoadRegister(*dwarf_reg)];
            push_add_offset(&mut steps, *offset);
            steps.push(PlanExprOp::Dereference {
                size: MemoryAccessSize::U64,
            });
            Ok(VariableLocation::ComputedAddress(steps))
        }
        VariableLocation::ComputedAddress(steps) => {
            let mut steps = steps.clone();
            steps.push(PlanExprOp::Dereference {
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
mod tests;
