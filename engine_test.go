package cedar

import (
	"context"
	"testing"
)

func TestCedarEngine_IsAuthorized(t *testing.T) {
	policy := `
	permit(
		principal == User::"alice",
		action    == Action::"update",
		resource  == Photo::"VacationPhoto94.jpg"
	);
	`
	engine, err := NewCedarEngine(context.TODO())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close(context.Background())
	err = engine.SetEntitiesFromJson(context.Background(), "[]")
	if err != nil {
		t.Fatal(err)
	}
	err = engine.SetPolicies(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("is authorized must return allow", func(t *testing.T) {
		isAuthorizedMustReturnAllow(t, engine, "User::\"alice\"", "Action::\"update\"", "Photo::\"VacationPhoto94.jpg\"")
	})
	t.Run("is authorized must return deny", func(t *testing.T) {
		isAuthorizedMustReturnDeny(t, engine, "User::\"alice\"", "Action::\"update\"", "Photo::\"VacationPhoto95.jpg\"")
	})
}
func isAuthorizedMustReturnAllow(t *testing.T, engine *CedarEngine, principal, action, resource string) {
	res, err := engine.IsAuthorized(context.Background(), EvalRequest{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   "{}",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res {
		t.Fatal("expected Allow")
	}
}

func isAuthorizedMustReturnDeny(t *testing.T, engine *CedarEngine, principal, action, resource string) {
	res, err := engine.IsAuthorized(context.Background(), EvalRequest{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   "{}",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res {
		t.Fatal("expected Deny")
	}
}

func TestCedarEngine_EvalWithResponse(t *testing.T) {
	policy := `
	@id("policy_test")
	@description("This is a test policy")
	permit(
		principal == User::"alice",
		action    == Action::"update",
		resource  == Photo::"VacationPhoto94.jpg"
	);
	`
	engine, err := NewCedarEngine(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close(context.Background())
	err = engine.SetEntitiesFromJson(context.Background(), "[]")
	if err != nil {
		t.Fatal(err)
	}
	err = engine.SetPolicies(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("eval with response must return allow", func(t *testing.T) {
		evalJSONMustReturnAllow(t, engine, "User::\"alice\"", "Action::\"update\"", "Photo::\"VacationPhoto94.jpg\"")
	})
	t.Run("eval with response must return deny", func(t *testing.T) {
		evalJSONMustReturnDeny(t, engine, "User::\"alice\"", "Action::\"update\"", "Photo::\"VacationPhoto95.jpg\"")
	})
}

func evalJSONMustReturnAllow(t *testing.T, engine *CedarEngine, principal, action, resource string) {
	res, err := engine.EvalWithResponse(context.Background(), EvalRequest{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   "{}",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Response.Decision != "Allow" {
		t.Fatal("expected Allow")
	}
	if res.Response.Diagnostics.Reason[0] != "policy0" { // First policy as it is the only one. Cedar engine fixes the policy name to policy<number> if not provided.
		t.Fatal("expected policy0 to be the reason for the decision")
	}
	if len(res.Response.Diagnostics.Errors) != 0 {
		t.Fatal("expected no errors")
	}
	if len(res.Annotations) != 1 {
		t.Fatal("expected one annotation")
	}
	if res.Annotations[0].Policy != "policy0" {
		t.Fatal("expected policy0")
	}
	if res.Annotations[0].Key != "description" {
		t.Fatal("expected key to be description")
	}
	if res.Annotations[0].Value != "This is a test policy" {
		t.Fatal("expected value to be This is a test policy")
	}
}

func evalJSONMustReturnDeny(t *testing.T, engine *CedarEngine, principal, action, resource string) {
	res, err := engine.EvalWithResponse(context.Background(), EvalRequest{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   "{}",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Response.Decision != "Deny" {
		t.Fatal("expected Deny")
	}
	if len(res.Response.Diagnostics.Reason) != 0 {
		t.Fatal("expected no reason for the decision")
	}
	if len(res.Response.Diagnostics.Errors) != 0 {
		t.Fatal("expected no errors")
	}
}
