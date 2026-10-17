# Open-run crash recovery (implemented in Milestone 1)

The file-backed store implements the following behavior for unsealed runs:

| Failure boundary | Required recovery |
|---|---|
| Before blob publication | Remove/ignore temp file; no accepted event |
| After durable blob, before log append | Orphan blob allowed |
| During final JSON write | Inspect terminal fragment under exclusive writer ownership |
| After complete line, before fsync/ack | Valid event may exist; retry must find same event ID |
| After fsync, before response | Event is durable; identical retry returns original |
| During index update | Ignore/rebuild derived index |
| During manifest publication | Retry verifies and returns a valid published manifest; invalid state fails closed |

Scan complete newline-delimited records and validate every one. Never skip a bad
middle line. A newline-terminated malformed record is corruption, even at the tail.
For a final fragment without newline, first distinguish syntactically complete JSON
from a genuinely unfinished token/container. Complete JSON with invalid schema,
hash, UTF-8, or unknown fields is corruption and must not be discarded. A complete
valid terminal Event is retained, its newline restored and synchronized. A fragment
that is malformed rather than truncated (e.g. an illegal token) is corruption.
Only a parser-confirmed incomplete final fragment may be truncated to the last
validated boundary. Truncation and repaired delimiters must be synchronized.

A sealed run is immutable: never repair or truncate a manifest-covered log; fail
verification if count, terminal anchor, blobs or signature disagree. A removed
manifest cannot be reliably detected by purely local open-run state: callers
expecting a sealed run must require a signed manifest and a trusted key. Whole-run
deletion needs an external inventory/anchor, which is out of scope.

Fault injection must exercise partial writes, write/sync failures and lost responses.
A successful acknowledgement must never refer to an event absent after supported
recovery. A failed request may nevertheless have committed; retries resolve this.
Process-crash tests are not proof of power-loss durability on all filesystems.

The tests inject partial append, log synchronization failure, derived-index failure,
ambiguous manifest publication, and response loss after successful synchronization.
They also construct incomplete, complete-without-newline, complete-invalid, and
malformed tails. Actual power-loss testing and filesystem-specific durability
characterization remain future work.
