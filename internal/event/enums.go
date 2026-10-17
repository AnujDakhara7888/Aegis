// Package event defines the version-one event contract and structural validation.
package event

import (
	"encoding/json"
	"fmt"
)

// Numeric enum assignments are permanent schema-v1 wire values.
// Zero is invalid; NONE and UNSPECIFIED are explicit values.
type Source uint16

const (
	SourceAgent       Source = 1
	SourceRecorder    Source = 2
	SourceModel       Source = 3
	SourceTool        Source = 4
	SourceProxy       Source = 5
	SourceKernel      Source = 6
	SourceAuditReader Source = 7
)

var sourceNames = [...]string{"", "AGENT", "RECORDER", "MODEL", "TOOL", "PROXY", "KERNEL", "AUDIT_READER"}

func (v Source) Valid() bool                  { return v > 0 && int(v) < len(sourceNames) }
func (v Source) String() string               { return enumName(uint16(v), sourceNames[:]) }
func (v Source) MarshalJSON() ([]byte, error) { return marshalEnum(uint16(v), sourceNames[:]) }
func (v *Source) UnmarshalJSON(b []byte) error {
	n, err := unmarshalEnum(b, sourceNames[:])
	if err != nil {
		return err
	}
	*v = Source(n)
	return nil
}

type Kind uint16

const (
	KindRunStarted          Kind = 1
	KindRunCompleted        Kind = 2
	KindRunFailed           Kind = 3
	KindDocumentRetrieved   Kind = 4
	KindModelRequested      Kind = 5
	KindModelResponded      Kind = 6
	KindToolRequested       Kind = 7
	KindToolCompleted       Kind = 8
	KindToolFailed          Kind = 9
	KindNetworkRequested    Kind = 10
	KindNetworkCompleted    Kind = 11
	KindApprovalRequested   Kind = 12
	KindApprovalGranted     Kind = 13
	KindApprovalRejected    Kind = 14
	KindPolicyAllowed       Kind = 15
	KindPolicyDenied        Kind = 16
	KindCapabilityAllowed   Kind = 17
	KindCapabilityDenied    Kind = 18
	KindSideEffectPrepared  Kind = 19
	KindSideEffectCommitted Kind = 20
	KindCheckpointCreated   Kind = 21
	KindBudgetUpdated       Kind = 22
	KindBudgetExceeded      Kind = 23
	KindRuntimeFailed       Kind = 24
	KindKernelEventObserved Kind = 25
)

var kindNames = [...]string{"", "RUN_STARTED", "RUN_COMPLETED", "RUN_FAILED", "DOCUMENT_RETRIEVED", "MODEL_REQUESTED", "MODEL_RESPONDED", "TOOL_REQUESTED", "TOOL_COMPLETED", "TOOL_FAILED", "NETWORK_REQUESTED", "NETWORK_COMPLETED", "APPROVAL_REQUESTED", "APPROVAL_GRANTED", "APPROVAL_REJECTED", "POLICY_ALLOWED", "POLICY_DENIED", "CAPABILITY_ALLOWED", "CAPABILITY_DENIED", "SIDE_EFFECT_PREPARED", "SIDE_EFFECT_COMMITTED", "CHECKPOINT_CREATED", "BUDGET_UPDATED", "BUDGET_EXCEEDED", "RUNTIME_FAILED", "KERNEL_EVENT_OBSERVED"}

func (v Kind) Valid() bool                  { return v > 0 && int(v) < len(kindNames) }
func (v Kind) String() string               { return enumName(uint16(v), kindNames[:]) }
func (v Kind) MarshalJSON() ([]byte, error) { return marshalEnum(uint16(v), kindNames[:]) }
func (v *Kind) UnmarshalJSON(b []byte) error {
	n, err := unmarshalEnum(b, kindNames[:])
	if err != nil {
		return err
	}
	*v = Kind(n)
	return nil
}

type Phase uint16

const (
	PhaseInstant  Phase = 1
	PhaseRequest  Phase = 2
	PhaseResponse Phase = 3
	PhaseStart    Phase = 4
	PhaseEnd      Phase = 5
)

var phaseNames = [...]string{"", "INSTANT", "REQUEST", "RESPONSE", "START", "END"}

func (v Phase) Valid() bool                  { return v > 0 && int(v) < len(phaseNames) }
func (v Phase) String() string               { return enumName(uint16(v), phaseNames[:]) }
func (v Phase) MarshalJSON() ([]byte, error) { return marshalEnum(uint16(v), phaseNames[:]) }
func (v *Phase) UnmarshalJSON(b []byte) error {
	n, err := unmarshalEnum(b, phaseNames[:])
	if err != nil {
		return err
	}
	*v = Phase(n)
	return nil
}

type PolicyDecision uint16

const (
	PolicyDecisionNone            PolicyDecision = 1
	PolicyDecisionAllow           PolicyDecision = 2
	PolicyDecisionDeny            PolicyDecision = 3
	PolicyDecisionRequireApproval PolicyDecision = 4
)

var policyDecisionNames = [...]string{"", "NONE", "ALLOW", "DENY", "REQUIRE_APPROVAL"}

func (v PolicyDecision) Valid() bool    { return v > 0 && int(v) < len(policyDecisionNames) }
func (v PolicyDecision) String() string { return enumName(uint16(v), policyDecisionNames[:]) }
func (v PolicyDecision) MarshalJSON() ([]byte, error) {
	return marshalEnum(uint16(v), policyDecisionNames[:])
}
func (v *PolicyDecision) UnmarshalJSON(b []byte) error {
	n, err := unmarshalEnum(b, policyDecisionNames[:])
	if err != nil {
		return err
	}
	*v = PolicyDecision(n)
	return nil
}

type SideEffectClass uint16

const (
	SideEffectClassNone              SideEffectClass = 1
	SideEffectClassPure              SideEffectClass = 2
	SideEffectClassRead              SideEffectClass = 3
	SideEffectClassReversibleWrite   SideEffectClass = 4
	SideEffectClassIrreversibleWrite SideEffectClass = 5
	SideEffectClassNondeterministic  SideEffectClass = 6
	SideEffectClassHumanApproval     SideEffectClass = 7
)

var sideEffectClassNames = [...]string{"", "NONE", "PURE", "READ", "REVERSIBLE_WRITE", "IRREVERSIBLE_WRITE", "NONDETERMINISTIC", "HUMAN_APPROVAL"}

func (v SideEffectClass) Valid() bool    { return v > 0 && int(v) < len(sideEffectClassNames) }
func (v SideEffectClass) String() string { return enumName(uint16(v), sideEffectClassNames[:]) }
func (v SideEffectClass) MarshalJSON() ([]byte, error) {
	return marshalEnum(uint16(v), sideEffectClassNames[:])
}
func (v *SideEffectClass) UnmarshalJSON(b []byte) error {
	n, err := unmarshalEnum(b, sideEffectClassNames[:])
	if err != nil {
		return err
	}
	*v = SideEffectClass(n)
	return nil
}

type ReplayBehavior uint16

const (
	ReplayBehaviorUnspecified     ReplayBehavior = 1
	ReplayBehaviorReexecute       ReplayBehavior = 2
	ReplayBehaviorRecordedResult  ReplayBehavior = 3
	ReplayBehaviorSimulate        ReplayBehavior = 4
	ReplayBehaviorNever           ReplayBehavior = 5
	ReplayBehaviorRequireApproval ReplayBehavior = 6
)

var replayBehaviorNames = [...]string{"", "UNSPECIFIED", "REEXECUTE", "RECORDED_RESULT", "SIMULATE", "NEVER", "REQUIRE_APPROVAL"}

func (v ReplayBehavior) Valid() bool    { return v > 0 && int(v) < len(replayBehaviorNames) }
func (v ReplayBehavior) String() string { return enumName(uint16(v), replayBehaviorNames[:]) }
func (v ReplayBehavior) MarshalJSON() ([]byte, error) {
	return marshalEnum(uint16(v), replayBehaviorNames[:])
}
func (v *ReplayBehavior) UnmarshalJSON(b []byte) error {
	n, err := unmarshalEnum(b, replayBehaviorNames[:])
	if err != nil {
		return err
	}
	*v = ReplayBehavior(n)
	return nil
}

func enumName(v uint16, names []string) string {
	if v == 0 || int(v) >= len(names) {
		return fmt.Sprintf("UNKNOWN(%d)", v)
	}
	return names[v]
}
func marshalEnum(v uint16, names []string) ([]byte, error) {
	if v == 0 || int(v) >= len(names) {
		return nil, fmt.Errorf("unknown enum value %d", v)
	}
	return json.Marshal(names[v])
}
func unmarshalEnum(b []byte, names []string) (uint16, error) {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return 0, fmt.Errorf("enum must be a string: %w", err)
	}
	for i := 1; i < len(names); i++ {
		if s == names[i] {
			return uint16(i), nil
		}
	}
	return 0, fmt.Errorf("unknown enum name %q", s)
}
