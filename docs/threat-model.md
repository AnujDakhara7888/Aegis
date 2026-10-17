# Threat model

Target for the sealed-recorder milestone: detect changes to a completed run made
by someone lacking the expected recorder private key. The expected public key must
come from a separately trusted configuration, never from the run being verified.

Untrusted: agent process, prompts/documents, generated content/arguments, external
responses, user tool code, and future WASM modules. Trusted: recorder and storage,
verification implementation, signing key, host OS, eventual proxy, AgentOS kernel,
and privileged audit reader. Labels such as KERNEL do not authenticate a client;
the future bridge must authenticate and preserve causal correlation explicitly.

Excluded: compromised recorder/OS, signing-key theft, recorder omissions, an
attacker able to rewrite history and access the key, physical attacks, full host
compromise, and effects outside instrumented boundaries. Local bearer auth does
not defend against a compromised local account. Payloads may contain secrets;
content addressing is not encryption or redaction. Raw payloads are never returned
by default in the planned API; storage permissions still matter.

Precise future claim: tamper-evident relative to the recorder’s signing key.
Current hashes are unauthenticated: an attacker may recompute a whole chain or
remove its tail. No signature, protected execution, or completeness claim is made.
