package nostrverify

import (
	"fmt"
	"reflect"

	"github.com/nbd-wtf/go-nostr"
)

func ValidateEventIDAndSignature(ev *nostr.Event) error {
	if ev == nil {
		return fmt.Errorf("nil event")
	}

	idOK, err := callBoolMethod(ev, "CheckID")
	if err != nil {
		return fmt.Errorf("check id: %w", err)
	}
	if !idOK {
		return fmt.Errorf("invalid event id")
	}

	sigOK, err := callBoolMethod(ev, "CheckSignature")
	if err != nil {
		return fmt.Errorf("check signature: %w", err)
	}
	if !sigOK {
		return fmt.Errorf("invalid event signature")
	}

	return nil
}

func callBoolMethod(target any, methodName string) (bool, error) {
	method := reflect.ValueOf(target).MethodByName(methodName)
	if !method.IsValid() {
		return false, fmt.Errorf("method %s not found", methodName)
	}

	results := method.Call(nil)
	switch len(results) {
	case 1:
		if results[0].Kind() != reflect.Bool {
			return false, fmt.Errorf("method %s did not return bool", methodName)
		}
		return results[0].Bool(), nil
	case 2:
		if results[0].Kind() != reflect.Bool {
			return false, fmt.Errorf("method %s first return is not bool", methodName)
		}
		if !results[1].IsNil() {
			err, ok := results[1].Interface().(error)
			if ok {
				return false, err
			}
			return false, fmt.Errorf("method %s returned non-error second value", methodName)
		}
		return results[0].Bool(), nil
	default:
		return false, fmt.Errorf("method %s has unsupported return signature", methodName)
	}
}
