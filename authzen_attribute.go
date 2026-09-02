// The tri-state attribute for the AuthZEN surface.
//
// Every attribute bag on the AuthZEN surface (subject/action/resource
// `properties`, and `context` on a request or a bulk envelope) holds facts the
// CALLER resolved from somewhere else: an identity provider, a trace
// propagator, a session store. Resolving a fact has three outcomes, and two of
// them are not the same thing:
//
//   - known: the source answered with a value. It is sent.
//   - absent: the source answered, and the answer is that there is no value.
//     Absence is a FACT, not a failure, so the member is omitted and the
//     request is sent - a policy that handles absence gets to handle it.
//   - unknown: the source could not answer. The request is NOT sent. Sending
//     it would have the gateway evaluate as though the attribute were absent,
//     and the resulting decision - and every audit of it - would record that
//     an attribute was weighed when nobody ever read it.
//
// A bare omission from a map[string]any collapses the second and third into
// one, and the collapse always resolves the wrong way: the unknown attribute
// gets dropped from the request, the server evaluates without it, and the
// caller is handed a verdict that names every attribute it weighed - including
// the one nobody could resolve. That is the exact failure the server's own
// adapter refuses on its side of the wire; this type is the same refusal on
// the client's side. The sibling SDKs carry the same type under the same
// three-state vocabulary.
//
// Where it may be used: inside the attribute bags, at any depth. Not on the
// structural members (Subject.ID, Action.Name, Resource.Type, ...): those are
// the identity of the question being asked, not data about it.
package axonflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// AuthZENAttributeState is which of the three states an attribute is in.
type AuthZENAttributeState string

const (
	// AuthZENAttributeKnown means the source answered with a value.
	AuthZENAttributeKnown AuthZENAttributeState = "known"
	// AuthZENAttributeAbsent means the source answered: there is no value.
	AuthZENAttributeAbsent AuthZENAttributeState = "absent"
	// AuthZENAttributeUnknown means the source could not answer.
	AuthZENAttributeUnknown AuthZENAttributeState = "unknown"
)

// AuthZENAttributeMarker is the member every tri-state attribute carries on a
// JSON boundary, and one of the two shapes the resolver recognises.
//
// It exists because recognising an attribute by its Go type alone has a silent
// failure mode in the dangerous direction: an attribute that crossed a
// boundary the type cannot cross - a queue, a worker, a cache that round-trips
// through JSON - comes back as an ordinary map, so an UNKNOWN one would be
// resolved as ordinary data and SENT. Recognising it by shape alone has the
// mirror failure: a caller's own bag carrying state/value/reason members would
// be read as an attribute, and a legitimate request refused. A marker closes
// both, and the sibling SDKs use the same key for the same reason.
const AuthZENAttributeMarker = "__axonflow_authzen_attribute__"

// Why an attribute could not be established.
//
// These mirror ADR-065's tri-state reason codes so an operator reading an SDK
// refusal and an operator reading a platform trace use the same words. They
// are CLIENT-LOCAL: an unknown attribute never reaches the wire, because the
// whole point is that the request is not sent. The reason is free-form on
// purpose - a closed set hand-copied from the platform would be a
// transcription that drifts, and nothing on the far side reads it.
const (
	AuthZENUnknownNotSupplied        = "attribute_not_supplied"
	AuthZENUnknownResolutionFailed   = "resolution_failed"
	AuthZENUnknownStale              = "stale"
	AuthZENUnknownSchemaMismatch     = "schema_mismatch"
	AuthZENUnknownClosureUnavailable = "closure_unavailable"
	AuthZENUnknownClosureTruncated   = "closure_truncated"
	AuthZENUnknownMalformedValue     = "malformed_value"
	AuthZENUnknownRequiredAbsent     = "required_attribute_absent"
)

// maxAuthZENAttributeDepth is how deep an attribute bag may nest before the
// SDK stops walking it.
//
// Without a bound, a bag that refers to itself recurses until the stack gives
// out, and the caller gets a runtime panic out of Evaluate - a failure mode
// nothing documents and no enforcement point recovers. A bound turns that into
// the same typed refusal every other unresolvable bag gets. 64 is far past
// anything a policy attribute path plausibly nests (the platform's own
// attribute paths are three or four segments) and far short of the stack. The
// sibling SDKs that walk untyped bags (Python, TypeScript) use the same bound;
// Java and Rust build requests from typed models and have no untyped walk to
// bound.
const maxAuthZENAttributeDepth = 64

// AuthZENAttribute is one policy-visible attribute in exactly one of three
// states. Construct it with AuthZENKnown, AuthZENAbsent or AuthZENUnknown;
// the zero value is deliberately unusable (it is recognised as no state at
// all and refused rather than sent).
//
// Collapsing absent into unknown is the defect this type exists to prevent,
// and it is not hypothetical: on the platform side an ABSENT subject type was
// read as the one supported value, so omitting the field bypassed the
// impersonation refusal that naming it correctly triggered.
type AuthZENAttribute struct {
	state  AuthZENAttributeState
	value  any
	reason string
}

// AuthZENKnown records that the source answered with this value.
func AuthZENKnown(value any) AuthZENAttribute {
	return AuthZENAttribute{state: AuthZENAttributeKnown, value: value}
}

// AuthZENAbsent records that the source answered: there is no value.
func AuthZENAbsent() AuthZENAttribute {
	return AuthZENAttribute{state: AuthZENAttributeAbsent}
}

// AuthZENUnknown records that the source could not answer, for the named
// reason.
//
// The reason travels into the refusal so an operator sees the cause and not
// just the effect; use one of the AuthZENUnknown* reason constants or free
// text. An empty reason is recorded as "no reason given" rather than
// weakening the state - an unknown with no reason still refuses the request.
//
// Construction is stricter in the siblings: Python raises and TypeScript
// throws on an empty reason, where Go rewrites it and Java accepts "" as-is.
// Code ported from those SDKs behaves the same here (a non-empty reason is
// relayed unchanged); code relying on Go's leniency does not port back.
func AuthZENUnknown(reason string) AuthZENAttribute {
	if strings.TrimSpace(reason) == "" {
		reason = "no reason given"
	}
	return AuthZENAttribute{state: AuthZENAttributeUnknown, reason: reason}
}

// State reports which of the three states this attribute is in.
func (a AuthZENAttribute) State() AuthZENAttributeState { return a.state }

// IsKnown reports whether the source answered with a value.
func (a AuthZENAttribute) IsKnown() bool { return a.state == AuthZENAttributeKnown }

// IsAbsent reports whether the source answered that there is no value.
func (a AuthZENAttribute) IsAbsent() bool { return a.state == AuthZENAttributeAbsent }

// IsUnknown reports whether the source could not answer.
func (a AuthZENAttribute) IsUnknown() bool { return a.state == AuthZENAttributeUnknown }

// Value returns the resolved value and whether the attribute is known.
//
// The boolean DOES collapse absent and unknown, so it is for inspection -
// logging, a debug view - and not for deciding what to send: nothing built on
// it can distinguish "there is no department" from "the directory was down".
func (a AuthZENAttribute) Value() (any, bool) { return a.value, a.IsKnown() }

// Reason returns why the source could not answer, or "" for the other states.
func (a AuthZENAttribute) Reason() string { return a.reason }

// String renders the attribute for logs; it never renders as its value alone,
// so a log line cannot read a state as data.
func (a AuthZENAttribute) String() string {
	switch a.state {
	case AuthZENAttributeKnown:
		return fmt.Sprintf("known(%v)", a.value)
	case AuthZENAttributeAbsent:
		return "absent"
	case AuthZENAttributeUnknown:
		return fmt.Sprintf("unknown(%s)", a.reason)
	default:
		return "authzen attribute (no state; construct with AuthZENKnown/AuthZENAbsent/AuthZENUnknown)"
	}
}

// MarshalJSON is the backstop UNDER the resolver, not the send path.
//
// Evaluate and EvaluateAll resolve every bag before encoding, so an attribute
// that reaches the encoder is one a future code path failed to resolve - or
// one a caller nested inside a container the resolver does not walk, such as
// its own struct. The rule then is the same rule the resolver applies, minus
// the abilities an encoder does not have:
//
//   - known encodes as its value, which is what resolution would have sent;
//   - absent FAILS: a value cannot omit itself from a container the resolver
//     never walked, and encoding null instead would turn "there is no value"
//     into the value null;
//   - unknown FAILS with the same typed refusal the resolver produces, so the
//     request is never sent. Evaluate unwraps it back into the
//     *AuthZENUnresolvedError the caller is documented to receive.
//
// To carry an attribute across a JSON boundary of your own (a queue, a cache),
// hand-build the marker document instead - a map holding
// AuthZENAttributeMarker: true, "state", and "value"/"reason" - which the
// resolver recognises exactly as it recognises the type itself.
func (a AuthZENAttribute) MarshalJSON() ([]byte, error) {
	switch a.state {
	case AuthZENAttributeKnown:
		return json.Marshal(a.value)
	case AuthZENAttributeAbsent:
		return nil, errors.New(
			"axonflow: an ABSENT attribute cannot encode itself: only the resolver can omit the member, " +
				"and it walks map[string]any and slices, not your own structs. Put the attribute in a " +
				"map[string]any bag, or omit the member yourself")
	case AuthZENAttributeUnknown:
		return nil, &AuthZENUnresolvedError{Reason: a.reason}
	default:
		return nil, errors.New(
			"axonflow: a zero-value AuthZENAttribute has no state; construct it with " +
				"AuthZENKnown, AuthZENAbsent or AuthZENUnknown")
	}
}

// AuthZENUnresolvedError is the SDK refusing, locally, to send a request that
// carries an attribute nobody could resolve. No HTTP request is made.
//
// It is deliberately NOT an *AuthZENError: that type is a refusal document the
// SERVER sent, and dressing a local refusal in it would tell the caller the
// gateway refused when the request never left the process. The code
// vocabulary is shared because the reasons are shared - see Code - but the
// types are distinct so errors.As can tell who declined.
//
// It is NOT retryable, and that is the opposite of what it first looks like.
// A source that could not answer this second may answer the next one - but
// that is a statement about a DIFFERENT request. This one carries the
// unresolved attribute inside it, so resending the identical request
// reproduces the identical refusal forever, and a retry loop would burn its
// whole budget on it. Re-resolve the attribute and build a new request; or,
// if the source proved there is no value, send it as an explicitly ABSENT
// attribute.
type AuthZENUnresolvedError struct {
	// Pointer is the JSON Pointer naming the member nobody could resolve,
	// in the server's own vocabulary (/evaluation/context/dept,
	// /evaluations/evaluations/0/resource/properties/owner, ...). Empty only
	// when the encoder backstop caught the attribute, where no pointer is
	// known.
	Pointer string
	// Reason is why the source could not answer, as the caller recorded it.
	Reason string
}

// Error renders the refusal.
func (e *AuthZENUnresolvedError) Error() string {
	if e == nil {
		return "<nil authzen unresolved error>"
	}
	at := e.Pointer
	if at == "" {
		at = "an attribute the resolver did not walk (it was nested inside a caller-owned container)"
	}
	return fmt.Sprintf(
		"axonflow: the attribute at %s could not be established (%s), so this request was not sent. "+
			"The gateway would have evaluated as though the attribute had no value, and the decision - "+
			"and every audit of it - would record that it was considered when nothing read it. "+
			"Establish the value, or send it as an explicitly ABSENT attribute if the source proved "+
			"there is none.",
		at, e.Reason)
}

// Code places the refusal in the shared AuthZEN vocabulary: an incomplete
// evaluation is an incomplete evaluation whoever notices it first. The type,
// not the code, is what distinguishes it from a server refusal.
func (e *AuthZENUnresolvedError) Code() AuthZENErrorCode {
	return AuthZENErrorCodeUnevaluableAttribute
}

// Retryable reports whether sending the same request again could give a
// different answer. It is always false: the refusal is frozen inside the
// request itself, so identical bytes reproduce the identical refusal.
// Re-resolve the attribute and build a NEW request.
func (e *AuthZENUnresolvedError) Retryable() bool {
	return false
}

// AsAuthZENUnresolvedError unwraps err and returns the local unresolved
// refusal when there is one, mirroring AsAuthZENError for the server's
// refusals:
//
//	dec, err := client.Evaluate(ctx, req)
//	if unres, ok := axonflow.AsAuthZENUnresolvedError(err); ok {
//	    log.Printf("re-resolve %s: %s", unres.Pointer, unres.Reason)
//	}
func AsAuthZENUnresolvedError(err error) (*AuthZENUnresolvedError, bool) {
	var e *AuthZENUnresolvedError
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// authzenAttributeParts is THE recogniser: the one predicate every write path
// consults, at every depth, to decide whether a value is a tri-state
// attribute.
//
// One function rather than a check per site, for two reasons proven the hard
// way in the sibling SDKs: a rule duplicated across sites gets fixed at the
// site a review names and stays broken one nesting level down; and two guards
// worded alike defeat a textual mutation harness, which mutates the first
// match and reports a survivor on the other.
//
// It recognises two shapes: the AuthZENAttribute type itself (by value or
// pointer), and the marker document an attribute becomes on the far side of a
// JSON boundary - a map carrying AuthZENAttributeMarker: true and a valid
// state. A map with the marker but a state this build does not know is
// reported as an attribute in the UNKNOWN state rather than passed through as
// data: it was declared to be an attribute, and the fail-open reading of a
// declaration this build cannot parse is exactly the collapse the type
// prevents.
//
// The siblings DIVERGE here, and this side is the deliberate one: Python and
// TypeScript currently treat a marker document with an unrecognised state as
// NOT-an-attribute and send it on the wire as data, marker and all - the
// fail-open reading. Go refuses. The sibling fail-open issues were filed
// 2026-09-02; until they land, an attribute round-tripped through a boundary
// by a NEWER build (one that knows more states) is refused by Go and silently
// sent by Python/TS.
func authzenAttributeParts(v any) (state AuthZENAttributeState, value any, reason string, ok bool) {
	switch a := v.(type) {
	case AuthZENAttribute:
		return a.state, a.value, a.reason, a.state != ""
	case *AuthZENAttribute:
		if a == nil {
			return "", nil, "", false
		}
		return a.state, a.value, a.reason, a.state != ""
	case map[string]any:
		if a[AuthZENAttributeMarker] != true {
			return "", nil, "", false
		}
		s, _ := a["state"].(string)
		r, _ := a["reason"].(string)
		switch AuthZENAttributeState(s) {
		case AuthZENAttributeKnown, AuthZENAttributeAbsent, AuthZENAttributeUnknown:
			return AuthZENAttributeState(s), a["value"], r, true
		default:
			return AuthZENAttributeUnknown, nil,
				fmt.Sprintf("the value is marked as a tri-state attribute but its state %q is not one this build knows", s),
				true
		}
	default:
		return "", nil, "", false
	}
}

// escapeAuthZENPointerToken escapes one JSON Pointer token per RFC 6901. A
// key containing a slash would otherwise produce a pointer naming a member
// that does not exist, on the refusal whose entire diagnostic value is the
// pointer.
func escapeAuthZENPointerToken(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
}

// resolveAuthZENValue resolves one value, recursing through containers. It is
// the ONE walker under every bag on the surface - the singular request's
// context and properties, the bulk envelope's shared base, and every bulk
// entry - so the rule cannot hold at one depth and fail at another.
//
// It returns the resolved value; drop=true when the value resolved to "omit
// this member" (an ABSENT attribute); and the typed refusal when an attribute
// is UNKNOWN. It never mutates the caller's containers: bags are rebuilt, so
// a caller can reuse a request after a refusal.
func resolveAuthZENValue(v any, pointer string, depth int) (resolved any, drop bool, err error) {
	if depth > maxAuthZENAttributeDepth {
		return nil, false, &AuthZENUnresolvedError{
			Pointer: pointer,
			Reason: fmt.Sprintf(
				"nests deeper than %d levels, which this SDK will not walk; a bag that refers to itself would otherwise recurse until the stack gave out",
				maxAuthZENAttributeDepth),
		}
	}

	if state, value, reason, ok := authzenAttributeParts(v); ok {
		switch state {
		case AuthZENAttributeKnown:
			// A known attribute may itself hold a container carrying more
			// attributes; resolving the payload keeps the rule uniform rather
			// than depending on how deeply a caller nested its resolver
			// output.
			return resolveAuthZENValue(value, pointer, depth+1)
		case AuthZENAttributeAbsent:
			return nil, true, nil
		default:
			return nil, false, &AuthZENUnresolvedError{Pointer: pointer, Reason: reason}
		}
	}

	switch c := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(c))
		for key, item := range c {
			r, d, err := resolveAuthZENValue(item, pointer+"/"+escapeAuthZENPointerToken(key), depth+1)
			if err != nil {
				return nil, false, err
			}
			if d {
				continue
			}
			out[key] = r
		}
		return out, false, nil
	case []any:
		return resolveAuthZENSlice(reflect.ValueOf(c), pointer, depth)
	}

	// Containers under other static types - a map[string]AuthZENAttribute, a
	// []AuthZENAttribute, a caller's own alias - are walked reflectively, so
	// an attribute cannot ride to the wire inside a container the fast paths
	// above happen not to name. Structs are NOT walked: a struct cannot be
	// rebuilt with a member omitted, so an attribute inside one is left for
	// the MarshalJSON backstop, which sends a known value and refuses the
	// other two states.
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return v, false, nil
		}
		out := make(map[string]any, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			key := iter.Key().String()
			r, d, err := resolveAuthZENValue(iter.Value().Interface(), pointer+"/"+escapeAuthZENPointerToken(key), depth+1)
			if err != nil {
				return nil, false, err
			}
			if d {
				continue
			}
			out[key] = r
		}
		return out, false, nil
	case reflect.Slice, reflect.Array:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			// []byte encodes as a base64 string, not as an array of values;
			// walking it would rewrite the encoding.
			return v, false, nil
		}
		return resolveAuthZENSlice(rv, pointer, depth)
	default:
		return v, false, nil
	}
}

// resolveAuthZENSlice walks one slice or array. An ABSENT element is dropped
// rather than left as a hole: a list with a gap in it is a different list,
// and the index a policy reads would shift under it either way; dropping is
// the reading that matches "there is no value here".
func resolveAuthZENSlice(rv reflect.Value, pointer string, depth int) (any, bool, error) {
	out := make([]any, 0, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		r, d, err := resolveAuthZENValue(rv.Index(i).Interface(), fmt.Sprintf("%s/%d", pointer, i), depth+1)
		if err != nil {
			return nil, false, err
		}
		if d {
			continue
		}
		out = append(out, r)
	}
	return out, false, nil
}

// resolveAuthZENBag resolves one attribute bag.
//
// ABSENCE DOES NOT CASCADE. A bag whose every member resolved absent is sent
// as an empty object, not deleted: the bag is the caller's structure and the
// attributes are the data inside it, and an SDK that removed a container the
// caller placed would be editing the question rather than resolving the
// answer. The lever a caller wants sits one level in, which is where the
// attributes are.
//
// A bag that is ITSELF attribute-shaped - a marker document where the object
// should be - is refused as malformed rather than resolved: whatever it held
// (a scalar for known, the drop signal for absent) is not a bag, and the
// sibling SDKs refuse the identical input with the identical code.
func resolveAuthZENBag(bag map[string]any, pointer string) (map[string]any, error) {
	if bag == nil {
		return nil, nil
	}
	resolved, drop, err := resolveAuthZENValue(bag, pointer, 0)
	if err != nil {
		return nil, err
	}
	out, ok := resolved.(map[string]any)
	if drop || !ok {
		return nil, &AuthZENError{
			Code:    AuthZENErrorCodeMalformedEnvelope,
			Pointer: pointer,
			Message: pointer + " must be an object",
		}
	}
	return out, nil
}

func resolveAuthZENSubject(subject *AuthZENSubject, at string) (*AuthZENSubject, error) {
	if subject == nil {
		return nil, nil
	}
	properties, err := resolveAuthZENBag(subject.Properties, at+"/subject/properties")
	if err != nil {
		return nil, err
	}
	out := *subject
	out.Properties = properties
	return &out, nil
}

func resolveAuthZENAction(action *AuthZENAction, at string) (*AuthZENAction, error) {
	if action == nil {
		return nil, nil
	}
	properties, err := resolveAuthZENBag(action.Properties, at+"/action/properties")
	if err != nil {
		return nil, err
	}
	out := *action
	out.Properties = properties
	return &out, nil
}

func resolveAuthZENResource(resource *AuthZENResource, at string) (*AuthZENResource, error) {
	if resource == nil {
		return nil, nil
	}
	properties, err := resolveAuthZENBag(resource.Properties, at+"/resource/properties")
	if err != nil {
		return nil, err
	}
	out := *resource
	out.Properties = properties
	return &out, nil
}

func resolveAuthZENRequest(request AuthZENRequest, at string) (AuthZENRequest, error) {
	subject, err := resolveAuthZENSubject(request.Subject, at)
	if err != nil {
		return AuthZENRequest{}, err
	}
	action, err := resolveAuthZENAction(request.Action, at)
	if err != nil {
		return AuthZENRequest{}, err
	}
	resource, err := resolveAuthZENResource(request.Resource, at)
	if err != nil {
		return AuthZENRequest{}, err
	}
	ctx, err := resolveAuthZENBag(request.Context, at+"/context")
	if err != nil {
		return AuthZENRequest{}, err
	}
	out := request
	out.Subject, out.Action, out.Resource, out.Context = subject, action, resource, ctx
	return out, nil
}

// resolveAuthZENEnvelope returns the envelope with every tri-state attribute
// resolved to the wire, or the typed refusal when an attribute is UNKNOWN.
//
// It runs on the one transport path both Evaluate and EvaluateAll share, so
// every write site on the surface funnels through the same walker: the
// singular request's four bags, the plural envelope's shared base, and each
// plural entry's four bags. BOTH envelope members are resolved when both are
// present, rather than the first one winning: the exactly-one-of rule lives
// in the generated validator, and an early return here would hide from it the
// violation it exists to refuse.
//
// The pointers match the server's own vocabulary - /evaluation/... for a
// singular envelope, /evaluations/evaluations/<i>/... for a plural entry - so
// a client-side refusal and a gateway refusal name the same member the same
// way.
func resolveAuthZENEnvelope(env AuthZENEnvelope) (AuthZENEnvelope, error) {
	out := AuthZENEnvelope{}
	if env.Evaluation != nil {
		resolved, err := resolveAuthZENRequest(*env.Evaluation, "/evaluation")
		if err != nil {
			return AuthZENEnvelope{}, err
		}
		out.Evaluation = &resolved
	}
	if env.Evaluations != nil {
		bulk := *env.Evaluations
		subject, err := resolveAuthZENSubject(bulk.Subject, "/evaluations")
		if err != nil {
			return AuthZENEnvelope{}, err
		}
		action, err := resolveAuthZENAction(bulk.Action, "/evaluations")
		if err != nil {
			return AuthZENEnvelope{}, err
		}
		resource, err := resolveAuthZENResource(bulk.Resource, "/evaluations")
		if err != nil {
			return AuthZENEnvelope{}, err
		}
		ctx, err := resolveAuthZENBag(bulk.Context, "/evaluations/context")
		if err != nil {
			return AuthZENEnvelope{}, err
		}
		bulk.Subject, bulk.Action, bulk.Resource, bulk.Context = subject, action, resource, ctx
		if bulk.Evaluations != nil {
			entries := make([]AuthZENRequest, len(bulk.Evaluations))
			for i, entry := range bulk.Evaluations {
				resolved, err := resolveAuthZENRequest(entry, fmt.Sprintf("/evaluations/evaluations/%d", i))
				if err != nil {
					return AuthZENEnvelope{}, err
				}
				entries[i] = resolved
			}
			bulk.Evaluations = entries
		}
		out.Evaluations = &bulk
	}
	return out, nil
}
