//! The response-leg evaluate → apply decision.

use crate::boundary::{InterceptedResponse, Mutation, Verdict};
use crate::capability::{CapabilityContext, CapabilitySet};

/// The result of evaluating + applying the response leg.
pub(super) enum ResponseDecision {
    /// Return the (possibly scrubbed) response to the workload.
    Return,
    /// Block the response (a control denial or a limit breach).
    Block,
}

/// Evaluate `res` against `controls`, applying any allowed mutations in place.
pub(super) fn evaluate_and_apply(
    controls: &CapabilitySet,
    res: &mut InterceptedResponse,
    cx: &CapabilityContext,
) -> ResponseDecision {
    match controls.evaluate_response(res, cx) {
        Verdict::Allow { mutations } => {
            apply_all(mutations, res);
            ResponseDecision::Return
        }
        Verdict::Deny { .. } => ResponseDecision::Block,
    }
}

/// Apply every response mutation (header redactions from leak-back scrubbing, etc.) in place.
/// Consumes the owned `Vec` and moves each mutation's value in (no secret copy).
fn apply_all(mutations: Vec<Mutation>, res: &mut InterceptedResponse) {
    // Response mutations only touch headers; the target is irrelevant on the response leg, so a
    // throwaway target absorbs the (unused) path/query edits.
    let mut scratch = crate::boundary::Target::new("", 0);
    for m in mutations {
        m.into_apply(&mut res.headers, &mut scratch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::{BodyRef, HeaderMap, InterceptedResponse, Target};
    use crate::capability::{CapabilityOutcome, CapabilitySet, EgressCapability};
    use credentials::DestinationPattern;

    use crate::audit::RequestId;

    fn cx(host: &str) -> CapabilityContext {
        CapabilityContext::new(RequestId::new("t"), 0, Target::new(host, 443))
    }

    #[test]
    fn response_controls_apply_their_mutations() {
        struct ScrubControl {
            pattern: DestinationPattern,
        }

        impl EgressCapability for ScrubControl {
            fn pattern(&self) -> &DestinationPattern {
                &self.pattern
            }

            fn on_request(
                &self,
                _req: &mut crate::boundary::InterceptedRequest,
                _cx: &CapabilityContext,
            ) -> CapabilityOutcome {
                CapabilityOutcome::none()
            }

            fn on_response(
                &self,
                res: &mut InterceptedResponse,
                _cx: &CapabilityContext,
            ) -> CapabilityOutcome {
                res.body = BodyRef::Bytes(b"[REDACTED]".to_vec());
                CapabilityOutcome::applied(vec![Mutation::SetHeader {
                    name: "X-Echo".to_string(),
                    value: zeroize::Zeroizing::new("[REDACTED]".to_string()),
                }])
            }
        }

        let mut headers = HeaderMap::new();
        headers.append("Location", "https://other.example/v2");
        headers.append("X-Echo", "secret");
        let mut res = InterceptedResponse::http(302, headers, BodyRef::Bytes(b"secret".to_vec()));
        let set = CapabilitySet::from_parts(vec![Box::new(ScrubControl {
            pattern: DestinationPattern::parse("api.example.com").unwrap(),
        })]);

        assert!(matches!(
            evaluate_and_apply(&set, &mut res, &cx("api.example.com")),
            ResponseDecision::Return
        ));
        assert_eq!(res.headers.get("x-echo"), Some("[REDACTED]"));
        assert_eq!(res.body.as_bytes(), b"[REDACTED]");
    }
}
