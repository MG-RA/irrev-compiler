# Implementation Plan: Meta Scope for Scope Addition Governance

## Overview

Implement `scope:meta.scope@0` - a foundational governance scope that enforces the 6-step Scope Addition Protocol at runtime. This scope validates new scope entries before they enter the meta-registry, preventing semantic deadlock and ensuring proper scope contracts.

## Key Refinements from Review (CRITICAL)

This plan incorporates essential hardening to prevent future fractures:

1. **Scope ID representation**: NO @version in `id` field - separate `version` field is canonical
2. **Witness wire format**: Canonical CBOR arrays (like hash-witness/0), excludes timestamp from witness_id
3. **Provenance completeness**: Both `registry_hash_before` AND `registry_hash_after` in witness
4. **Validation severity**: Tri-state (error/warn/info) with explicit Phase 1 vs Phase 2 rules
5. **Error type separation**: New `RegistryGateError` (not overloading `DeclareCostError`)
6. **Full graph cycle detection**: DFS over entire registry + candidate, not just local deps
7. **Meta scope completeness**: scope:meta.scope MUST have all Phase 2 fields (can't be stub)
8. **Canonical registry hashing**: Registry hashed via canonical CBOR (prevents drift)

## User Requirements (Confirmed)

- **Contract Level**: Hybrid approach - Phase 1 structure (name allowlist) with optional Phase 2 fields for future extension
- **Protocol Enforcement**: Runtime enforcement - registry gate rejects invalid scopes
- **Implementation Location**: Rust-only in `admit_cli` - fast, authoritative, no circular dependencies

## Architecture

### Three-Layer Governance Model

1. **Compiler admissibility** - Rust-level validation (fast, authoritative)
2. **Scope admissibility** - Scope-level contracts (documented, checkable)
3. **Scope registry** - Meta-registry allowlist (gated, versioned)

### Key Patterns

- **Foundation Pattern**: Meta scope sits at base of scope dependency DAG
- **Attestation Pattern**: Every scope addition emits validation witness
- **Bridge Pattern**: Scope addition crosses from "proposed" to "registered" with ceremony
- **Self-Bootstrap**: Meta scope validates itself via Rust (no ADM circularity)

## Implementation Steps

### Step 1: Extend Core Types

**File**: `crates/admit_cli/src/types.rs`

Add new types for Phase 2 metadata (all optional for backward compatibility):

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaRegistryScope {
    // Phase 1 (required)
    // CRITICAL: id MUST NOT contain @version - version is separate field
    // Format: "scope:domain.name" (no @version suffix)
    pub id: String,
    pub version: u32,

    // Phase 2 (optional, forward-compatible)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_schema_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<ScopePhase>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub deterministic: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub foundational: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub emits: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumes: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub deps: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<ScopeRole>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScopePhase {
    P0, P1, P2, P3, P4,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScopeRole {
    Foundation, Transform, Verification,
    Governance, Integration, Application,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeAdditionWitness {
    pub schema_id: String,              // "scope-addition-witness/0"
    pub schema_version: u32,
    pub scope_id: String,               // "scope:domain.name" (no @version)
    pub scope_version: u32,
    pub validation_timestamp: String,   // ISO-8601 UTC, excluded from witness_id
    pub validations: Vec<ScopeValidation>,
    pub registry_version_before: u32,
    pub registry_version_after: u32,
    pub registry_hash_before: String,   // CRITICAL: hash before mutation
    pub registry_hash_after: String,    // Hash after mutation
}

// Witness identity payload (for deterministic witness_id calculation)
// Excludes validation_timestamp and freeform messages for stable IDs
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ScopeAdditionWitnessIdPayload {
    pub scope_id: String,
    pub scope_version: u32,
    pub validation_checks: Vec<String>,  // Just check names, not messages
    pub registry_version_before: u32,
    pub registry_version_after: u32,
    pub registry_hash_before: String,
    pub registry_hash_after: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScopeValidationSeverity {
    Error,  // Blocks addition
    Warn,   // Doesn't block (unless strict mode)
    Info,   // Informational only
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeValidation {
    pub check: String,
    pub severity: ScopeValidationSeverity,
    pub passed: bool,
    pub message: Option<String>,
}
```

Add new error type (don't overload DeclareCostError):

```rust
#[derive(Debug)]
pub enum RegistryGateError {
    ScopeIdMalformed { scope_id: String, reason: String },
    ScopeIdContainsVersion { scope_id: String },
    ScopeVersionMismatch { id_version: u32, field_version: u32 },
    ScopeSnapshotSchemaMissing { scope_id: String, schema_id: String },
    ScopeSnapshotSchemaWrongKind { scope_id: String, schema_id: String, found_kind: String },
    ScopeEmitsSchemaUnknown { scope_id: String, schema_id: String },
    ScopeConsumesSchemaUnknown { scope_id: String, schema_id: String },
    ScopeDependencyCycle { scope_id: String, cycle: Vec<String> },
    ScopeDependencyMissing { scope_id: String, dep_id: String },
    MetaScopeMustBeComplete { scope_id: String, missing_field: String },
    ValidationFailed { scope_id: String, errors: Vec<String> },
    InvalidValidationLevel(String),
    Io(String),
    Json(String),
}
```

### Step 2: Create Validation Logic

**File**: `crates/admit_cli/src/scope_validation.rs` (NEW)

Implement 6-step protocol validation:

```rust
pub enum ScopeValidationLevel {
    Phase1,  // Name + basic structure only
    Phase2,  // Full contract validation
}

pub struct ScopeValidator {
    registry: MetaRegistryV0,
    level: ScopeValidationLevel,
}

impl ScopeValidator {
    // Step 1: Name + Boundary
    // CRITICAL: id MUST NOT contain @version
    pub fn validate_scope_id(&self, scope_id: &str) -> Result<(), RegistryGateError>

    // Step 2: Snapshot Schema (with kind checking)
    pub fn validate_snapshot_schema(&self, scope: &MetaRegistryScope) -> Result<(), RegistryGateError>

    // Step 3: Predicate Family (emits)
    pub fn validate_emits(&self, scope: &MetaRegistryScope) -> Result<(), RegistryGateError>

    // Step 4: Mechanism Family (consumes)
    pub fn validate_consumes(&self, scope: &MetaRegistryScope) -> Result<(), RegistryGateError>

    // Step 5: Dependencies (full graph cycle detection)
    pub fn validate_dependencies(&self, scope: &MetaRegistryScope) -> Result<(), RegistryGateError>

    // Step 6: Contract reference (Phase 2 only)
    pub fn validate_contract(&self, scope: &MetaRegistryScope, meta_root: &Path) -> Result<(), RegistryGateError>

    // Special: Meta scope must be complete
    pub fn validate_meta_scope_completeness(&self, scope: &MetaRegistryScope) -> Result<(), RegistryGateError>

    // Full pipeline with severity-aware validation
    pub fn validate_scope_addition(&self, scope: &MetaRegistryScope, meta_root: Option<&Path>) -> Vec<ScopeValidation>

    // Full graph cycle detection (not just local deps)
    fn detect_dependency_cycle(&self, candidate_scope: &MetaRegistryScope) -> Option<Vec<String>>

    // Compute witness_id deterministically (excludes timestamp and messages)
    pub fn compute_witness_id(witness: &ScopeAdditionWitness) -> String
}
```

**Validation rules** (with severity levels):

**Phase 1 (errors block addition)**:
- Scope ID format: `scope:domain.name` (NO @version suffix - version is separate field)
- `id` must start with `scope:`
- `id` must NOT contain `@` character
- `id` domain part: lowercase, dots/underscores only
- Version must be non-negative integer in separate field
- No duplicate (id, version) pairs in registry
- Valid UTF-8 in all string fields

**Phase 2 (errors for invalid references, warnings for missing optional metadata)**:
- Snapshot schema existence (error if provided but missing)
- Snapshot schema kind check (error if provided but wrong kind - must be "snapshot")
- Emitted witness schemas exist (error if provided but missing)
- Consumed witness schemas exist (error if provided but missing)
- Dependencies exist in registry (error if provided but missing)
- No circular dependencies - full graph DFS from candidate node (error)
- Contract file exists (error if provided but missing file)
- Missing optional metadata (warn only - phase, deterministic, role, etc.)

**Special rule for scope:meta.scope**:
- All Phase 2 fields MUST be present (errors not warnings)
- Contract must exist (error if missing)
- Emits must include "scope-addition-witness/0"
- This prevents meta.scope being admitted as incomplete stub

### Step 3: Add CLI Commands

**File**: `crates/admit_cli/src/main.rs`

Add scope management subcommands with proper scope ID parsing:

```rust
#[derive(Subcommand)]
enum RegistryCommands {
    Init(RegistryInitArgs),
    Build(RegistryBuildArgs),
    Verify(RegistryVerifyArgs),
    ScopeAdd(ScopeAddArgs),
    ScopeVerify(ScopeVerifyArgs),
    ScopeList(ScopeListArgs),
    ScopeShow(ScopeShowArgs),
}

#[derive(Parser)]
struct ScopeAddArgs {
    /// Scope (format: "scope:domain.name@version" OR separate --scope-id and --version)
    #[arg(long, conflicts_with_all = &["scope_id", "version"])]
    scope: Option<String>,

    /// Scope ID (format: "scope:domain.name" - NO @version)
    #[arg(long, requires = "version")]
    scope_id: Option<String>,

    /// Scope version number
    #[arg(long)]
    version: Option<u32>,

    // ... Phase 2 optional fields ...
}
```

**Parsing logic**: CLI accepts either:
- `--scope scope:hash.content@0` (parses into id="scope:hash.content", version=0)
- `--scope-id scope:hash.content --version 0` (explicit separation)

Commands:
- `scope-add`: Add new scope with validation, emits ScopeAdditionWitness
- `scope-verify`: Verify existing scope passes validation
- `scope-list`: List all scopes (with filters by phase/role)
- `scope-show`: Show detailed scope info in text or JSON

### Step 4: Implement CLI Handlers

**File**: `crates/admit_cli/src/scope_commands.rs` (NEW)

Implement command handlers with proper witness generation:

```rust
pub fn scope_add(args: ScopeAddArgs) -> Result<ScopeAdditionWitness, RegistryGateError>
pub fn scope_verify(args: ScopeVerifyArgs) -> Result<Vec<ScopeValidation>, RegistryGateError>
pub fn scope_list(args: ScopeListArgs) -> Result<Vec<MetaRegistryScope>, RegistryGateError>
pub fn scope_show(args: ScopeShowArgs) -> Result<MetaRegistryScope, RegistryGateError>
```

**Flow for `scope_add`** (with proper provenance):
1. Load existing registry (JSON from disk)
2. Parse scope ID from args (handle both `--scope` and `--scope-id/--version`)
3. Validate ID format (no @version in id field)
4. Build new scope entry from CLI args
5. Hash registry BEFORE mutation (registry_hash_before)
6. Validate using `ScopeValidator` with severity-aware checks
7. Check all ERROR-severity validations passed (warnings don't block)
8. Add to registry, increment `registry_version`
9. Normalize registry (sort, dedup check)
10. Encode canonical CBOR and hash (registry_hash_after)
11. Write back to disk (unless `--dry-run`)
12. Create `ScopeAdditionWitness` with both before/after hashes
13. Compute deterministic witness_id (exclude timestamp and messages)
14. Optionally store witness as artifact (if --artifacts-root provided)
15. Return witness for display

### Step 5: Write Meta Scope Contract

**File**: `meta/meta-scope-contract.md` (NEW)

Create contract documentation following the pattern from `hash-scope-contract.md`:

```markdown
# Meta Scope Contract: `scope:meta.scope@0`

## Purpose
Governs scope additions to the meta-registry by enforcing the 6-step Scope Addition Protocol.

## Primitives
- Scope ID validation
- Schema reference validation
- Dependency graph validation
- Contract existence validation

## Operations
- scope.validate_addition(scope_entry) -> ScopeAdditionWitness
- scope.verify_contract(scope_id) -> Vec<ScopeValidation>
- scope.detect_cycle(scope_id, deps) -> Option<Vec<String>>

## Witnesses
- ScopeAdditionWitness (schema: scope-addition-witness/0)

## Laws
1. Name determinism: scope_id format must be `scope:domain.name@version`
2. Reference completeness: All schema_ids and dep scope_ids must exist
3. Acyclicity: Dependency graph must be acyclic (DAG)
4. Self-governance: Meta scope validates itself via Rust (no circularity)

## Constraints
- Forbids: Circular dependencies, unknown schema refs, malformed scope IDs
- Requires: Lowercase domain names, explicit versions, valid UTF-8

## Dependencies
- Meta-registry/0 (scope and schema registry)
- Canonical CBOR encoding rules
```

### Step 6: Bootstrap Meta Scope & Define Wire Format

**File**: `out/meta-registry.json`

Add `scope:meta.scope@0` entry with full Phase 2 metadata (NOTE: id has NO @version):

```json
{
  "schema_id": "meta-registry/0",
  "schema_version": 0,
  "registry_version": 1,
  "stdlib": [
    {
      "module_id": "module:irrev_std@1"
    }
  ],
  "schemas": [
    {
      "id": "meta-registry/0",
      "schema_version": 0,
      "kind": "meta_registry",
      "canonical_encoding": "canonical-cbor"
    },
    {
      "id": "scope-addition-witness/0",
      "schema_version": 0,
      "kind": "scope_addition_witness",
      "canonical_encoding": "canonical-cbor"
    },
    {
      "id": "admissibility-witness/1",
      "schema_version": 1,
      "kind": "witness",
      "canonical_encoding": "canonical-cbor"
    },
    {
      "id": "hash-witness/0",
      "schema_version": 0,
      "kind": "hash_witness",
      "canonical_encoding": "canonical-cbor"
    }
  ],
  "scopes": [
    {
      "id": "scope:meta.scope",
      "version": 0,
      "phase": "p2",
      "deterministic": true,
      "foundational": true,
      "emits": ["scope-addition-witness/0"],
      "consumes": [],
      "deps": [],
      "role": "governance",
      "contract_ref": "meta/meta-scope-contract.md"
    },
    {
      "id": "scope:meta.registry",
      "version": 0
    },
    {
      "id": "scope:main",
      "version": 0
    },
    {
      "id": "scope:hash.content",
      "version": 0,
      "phase": "p0",
      "deterministic": true,
      "foundational": true,
      "emits": ["hash-witness/0"],
      "consumes": [],
      "deps": [],
      "role": "foundation",
      "contract_ref": "meta/hash-scope-contract.md"
    }
  ]
}
```

**Wire Format Specification** (add to `scope_validation.rs`):

```rust
// Canonical CBOR wire format for scope-addition-witness/0
// Uses deterministic array encoding (no map keys to sort)
// Position-locked structure prevents drift

// ScopeAdditionWitnessIdPayload (for witness_id calculation)
// CBOR array with 7 elements:
// [
//   0: scope_id (text),
//   1: scope_version (uint),
//   2: validation_checks (array of text - check names only),
//   3: registry_version_before (uint),
//   4: registry_version_after (uint),
//   5: registry_hash_before (text, hex),
//   6: registry_hash_after (text, hex)
// ]

// Full ScopeAdditionWitness (for storage/emission)
// CBOR array with 9 elements:
// [
//   0: schema_id (text),
//   1: schema_version (uint),
//   2: scope_id (text),
//   3: scope_version (uint),
//   4: validation_timestamp (text, ISO-8601 UTC),
//   5: validations (array of validation structs),
//   6: registry_version_before (uint),
//   7: registry_version_after (uint),
//   8: registry_provenance (map with before/after hashes)
// ]

// Key invariant: witness_id = sha256(canonical_cbor(identity_payload))
// Timestamp excluded from witness_id for deterministic identity
```

**Golden Fixture** (add to tests): Pin exact CBOR bytes for meta scope self-validation witness

### Step 7: Add Tests

**File**: `crates/admit_cli/tests/scope_validation.rs` (NEW)

Test cases:
- `test_scope_id_validation_valid()` - Valid scope IDs pass
- `test_scope_id_validation_invalid()` - Invalid IDs rejected
- `test_snapshot_schema_validation()` - Schema existence checked
- `test_dependency_cycle_detection()` - Cycles detected
- `test_meta_scope_validates_itself()` - Golden fixture: meta scope passes own validation
- `test_scope_add_command()` - CLI integration test
- `test_phase1_backward_compatibility()` - Existing minimal entries still valid

### Step 8: Update Module Exports

**File**: `crates/admit_cli/src/lib.rs`

Export new modules:

```rust
pub mod scope_validation;
pub mod scope_commands;
```

## Critical Files Summary

### Files to Create (4)
1. `crates/admit_cli/src/scope_validation.rs` - Core validation logic
2. `crates/admit_cli/src/scope_commands.rs` - CLI command implementations
3. `meta/meta-scope-contract.md` - Meta scope contract documentation
4. `crates/admit_cli/tests/scope_validation.rs` - Test suite

### Files to Modify (5)
1. `crates/admit_cli/src/types.rs` - Extend types with Phase 2 fields
2. `crates/admit_cli/src/main.rs` - Add CLI commands
3. `crates/admit_cli/src/lib.rs` - Export new modules
4. `crates/admit_cli/src/registry.rs` - Integrate validation (optional)
5. `out/meta-registry.json` - Bootstrap meta scope entry

### Files to Reference (3)
1. `meta/hash-scope-contract.md` - Contract template
2. `meta/oss/scope-addition-protocol-v0.md` - Protocol specification
3. `crates/admit_cli/src/internal.rs` - Reuse hash utilities

## Verification Plan

### Unit Tests
```bash
cd irrev-compiler
cargo test --package admit_cli scope_validation
```

Expected: All tests pass, including golden fixture for meta scope self-validation.

### CLI Commands
```bash
# List current scopes
cargo run --bin admit-cli -- registry scope-list \
  --registry out/meta-registry.json

# Verify meta scope validates itself
cargo run --bin admit-cli -- registry scope-verify \
  --scope-id "scope:meta.scope" \
  --validation-level phase2 \
  --registry out/meta-registry.json

# Add a new test scope
cargo run --bin admit-cli -- registry scope-add \
  --scope-id "scope:test.demo" \
  --version 0 \
  --phase p1 \
  --deterministic true \
  --registry out/meta-registry.json \
  --dry-run

# Show scope details
cargo run --bin admit-cli -- registry scope-show \
  "scope:hash.content" \
  --registry out/meta-registry.json \
  --json
```

Expected outputs:
- `scope-list`: Shows all 4 scopes (meta.scope, meta.registry, main, hash.content)
- `scope-verify`: All validations pass for meta scope
- `scope-add`: Validation succeeds, witness emitted
- `scope-show`: Full scope details displayed

### Integration Test
```bash
# Build the registry with new meta scope entry
cargo run --bin admit-cli -- registry build \
  --input out/meta-registry.json \
  --artifacts-root out/artifacts

# Verify ledger references registry hash
cargo run --bin admit-cli -- registry verify \
  --artifacts-root out/artifacts \
  --ledger out/ledger.jsonl
```

Expected: Registry builds successfully, all artifact hashes match.

### Backward Compatibility Test
1. Existing registry entries (without Phase 2 fields) should still load
2. Phase 1 validation level should accept minimal entries
3. Phase 2 validation should warn (not error) on missing optional fields

## Migration Strategy

### Phase 1 (Immediate)
- All new fields are optional - existing entries remain valid
- CLI defaults to `--validation-level=phase1`
- Gradual rollout: only new scopes use Phase 2 metadata

### Phase 2 (Future)
- Document all existing scopes with contracts
- Add Phase 2 metadata to existing scope entries
- Change CLI default to `--validation-level=phase2`
- Enforce in CI/CD pipelines

## Design Decisions & Trade-offs

### 1. Scope ID Representation (CRITICAL FIX)
**Chosen**: Separate `id` and `version` fields, NO @version in id string
- **Registry format**: `{"id": "scope:hash.content", "version": 0}`
- **CLI convenience**: Accepts `--scope scope:hash.content@0` OR `--scope-id scope:hash.content --version 0`
- **Rationale**: Single source of truth for version, prevents fracture between string and field
- **Validation**: Error if `id` contains `@` character

### 2. Witness Wire Format (FOLLOWING HASH PATTERN)
**Chosen**: Canonical CBOR arrays with position-locked structure
- **Identity payload excludes**: timestamp, freeform messages
- **Provenance**: Both registry_hash_before AND registry_hash_after
- **Rationale**: Prevents CBOR drift, enables deterministic witness_id, proves transition
- **Golden fixture**: Pin exact CBOR bytes for meta scope self-validation

### 3. Validation Severity (TRI-STATE)
**Chosen**: Error/Warn/Info severity levels
- **Phase 1 errors**: Malformed ID, contains @, invalid UTF-8, duplicates
- **Phase 2 errors**: Invalid references (when present), cycles, missing contract file (when present)
- **Phase 2 warnings**: Missing optional metadata (phase, deterministic, role, etc.)
- **Rationale**: Enables gradual migration without blocking, explicit about what blocks

### 4. Error Type Separation
**Chosen**: New `RegistryGateError` type, NOT `DeclareCostError`
- **Rationale**: Scope governance is separate domain, enables better error messages and future extensibility
- **Converts to CLI exit status cleanly

### 5. Rust-Only Validation (AVOIDING CIRCULARITY)
**Chosen**: Implement in Rust, not ADM
- **Pro**: Avoids circular dependency (meta scope validates itself), fast, authoritative
- **Pro**: Meta scope is special - bootstrap logic belongs in foundational layer
- **Con**: Not extensible without code changes (acceptable for core governance)
- **Special rule**: scope:meta.scope MUST have all Phase 2 fields (errors not warnings)

### 6. Dependency Validation (FULL GRAPH)
**Chosen**: Full graph cycle detection with DFS, not just local deps
- **Algorithm**: Build adjacency map of all registry scopes + candidate, run DFS from candidate
- **Rationale**: Cycles can be indirect (A→B→C→A), must check entire graph
- **Deterministic**: Stable cycle path reporting

### 7. Snapshot Schema Validation (PRECISE)
**Chosen**: Check existence AND kind (if schema has kind field)
- **Error if**: Schema missing from registry when snapshot_schema_id provided
- **Error if**: Schema exists but kind != "snapshot" (when kind field present)
- **Rationale**: Prevents accidental reference to witness schemas as snapshot schemas

### 8. Optional Phase 2 Fields (EXCEPT META SCOPE)
**Chosen**: All Phase 2 fields are `Option<T>` EXCEPT for scope:meta.scope itself
- **Pro**: Backward compatible, gradual migration for normal scopes
- **Exception**: Meta scope must be complete (foundation governance can't be a stub)
- **Rationale**: Enables ecosystem to adopt slowly while ensuring governance is rigorous

## Additional Refinements Applied

### Canonical Registry Hashing
- Meta-registry hashed using canonical CBOR (same as hash-witness/0)
- Registry JSON on disk, but hash computed from canonical CBOR encoding
- Prevents drift from formatting/ordering changes
- `registry_hash = sha256(canonical_cbor(meta_registry_v0))`

### Scope ID Parsing
- CLI helper function: `parse_scope_spec(spec: &str) -> (String, u32)`
- Handles both formats: `"scope:hash.content@0"` → `("scope:hash.content", 0)`
- Validation: Reject if parsed id still contains `@`
- Single source of truth: version field in struct

### Meta Scope Self-Validation Bootstrap
- Special case in validator: `if scope_id == "scope:meta.scope"`
- Requires all Phase 2 fields present (errors not warnings)
- Contract must exist
- Emits must include "scope-addition-witness/0"
- Prevents incomplete governance stub

### Future: Unit Registry
- Same pattern can extend to `"units": []` section in meta-registry
- Unit entries admitted by meta.scope
- Cost events become structurally checkable: `{"quantity": 1000, "unit_id": "unit:byte"}`
- Deferred to Phase 3 but architecture supports it

## Success Criteria

### Core Functionality
- [ ] Scope ID validation rejects `@` in id field
- [ ] CLI parses both `--scope scope:x@0` and `--scope-id scope:x --version 0`
- [ ] Witness includes both registry_hash_before and registry_hash_after
- [ ] Witness_id excludes timestamp and messages (deterministic)
- [ ] Full graph cycle detection (not just local deps)
- [ ] Severity levels work (error blocks, warn doesn't)
- [ ] RegistryGateError used (not DeclareCostError)

### Testing
- [ ] All unit tests pass
- [ ] Meta scope validates itself (golden fixture with exact CBOR bytes)
- [ ] Golden fixture locks wire format for scope-addition-witness/0
- [ ] Snapshot schema kind validation works
- [ ] Dependency cycle test with indirect cycle (A→B→C→A)
- [ ] Backward compatibility: existing minimal entries still valid

### CLI & Integration
- [ ] CLI commands work end-to-end (add, verify, list, show)
- [ ] New scope entries can include Phase 2 metadata
- [ ] Phase 1 validation level accepts minimal entries
- [ ] Phase 2 validation level warns on missing optional fields
- [ ] Unknown schema references are rejected (errors)
- [ ] Registry version increments correctly on scope addition
- [ ] Canonical CBOR hashing for registry works

### Documentation
- [ ] Documentation complete and follows hash scope pattern
- [ ] Wire format specification documented (array positions)
- [ ] Scope addition witness is emitted with all validations
- [ ] Contract defines primitives, operations, witnesses, laws

## Rollout Plan

1. **Week 1**: Implement core types and validation logic
2. **Week 2**: Add CLI commands and tests
3. **Week 3**: Write documentation and bootstrap meta scope
4. **Week 4**: Internal testing and iteration
5. **Week 5**: Gradual rollout, monitor for issues
6. **Week 6+**: Add Phase 2 metadata to existing scopes
