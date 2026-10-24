package osquery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// maxEventRows bounds the rows of one pushed snapshot event.
const maxEventRows = 20000

// ValidateEvent checks one pushed log event (receiver.Config validation).
// Pushed content is untrusted: an event must be an osquery result event of a
// pack query, with a plausible host identifier and a bounded number of rows.
// The content is only ever parsed as data.
func ValidateEvent(event []byte) error {
	var ev logEvent
	dec := json.NewDecoder(bytes.NewReader(event))
	dec.UseNumber()
	if err := dec.Decode(&ev); err != nil {
		return errors.New("not an osquery result event")
	}
	if _, ok := queryOf(ev.Name); !ok {
		return fmt.Errorf("the query name is not one of the Meiscope pack's queries")
	}
	if h := ev.HostIdentifier; h == "" || len(h) > 253 {
		return errors.New("hostIdentifier is missing or too long")
	}
	if len(ev.Snapshot) > maxEventRows {
		return fmt.Errorf("a snapshot has more than %d rows", maxEventRows)
	}
	if ev.Snapshot == nil && ev.Columns == nil {
		return errors.New("the event has neither a snapshot nor columns")
	}
	return nil
}
