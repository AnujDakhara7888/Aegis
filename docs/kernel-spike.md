# Thin AgentOS feasibility plan

Blocked on the correct SBUnix/RISC-V source repository. No kernel source, syscall,
filename or device interface is assumed. Do not create an aegis-sbunix checkout yet.
Start the investigation after the basic recorder and deterministic demo, before
broad replay/UI work. The runtime and kernel will eventually be separate repositories.

Inspect and cite actual source locations for process structure/creation/teardown,
syscall dispatch, file open and user argument copying, scheduler accounting,
logging/device interfaces, QEMU serial output, build system and existing tests.
Document available resource enforcement and an achievable bridge mechanism.

Smallest proof: an agent process without read authority attempts to open `/secret`;
the kernel denies it and emits a versioned audit event. Record agent/process ID,
operation, resource identifier or stable digest, optional capability ID, result,
reason code and kernel-local sequence. Use a bounded ring buffer and a privileged
reader if supported; investigate overflow signaling and causal correlation before
selecting the syscall/device mechanism. Kernel sequence is not recorder order.

Preferred path: ring → privileged reader → verified QEMU/host output bridge → host
adapter → recorder. Preserve a tool-request correlation ID; an unrelated kernel
log next to an application event is insufficient evidence.

Acceptance timeline: DOCUMENT_RETRIEVED → MODEL_RESPONDED → TOOL_REQUESTED →
CAPABILITY_DENIED → KERNEL_EVENT_OBSERVED → TOOL_FAILED → RUN_FAILED. Demonstrate
one real denial and the causal edge. Do not describe application mocks as kernel
enforcement. Document source-informed tradeoffs in an ADR before modifying SBUnix.
