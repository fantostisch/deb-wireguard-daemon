package api

import (
	"encoding/json"
	"fmt"
	"net/http"
)

var (
	MissingPostParameter = Error{"missing_post_parameter"}
	UserIDNotSupplied    = Error{"user_id_not_supplied"}
	InvalidPublicKey     = Error{"invalid_public_key"}
	ConfigNotFound       = Error{"config_not_found"}
	UserAlreadyEnabled   = Error{"user_already_enabled"}
	UserAlreadyDisabled  = Error{"user_already_disabled"}
	NoIPAvailable        = Error{"no_ip_available"}
)

type Error struct {
	Type string
}

func (e Error) Error() string {
	return e.Type
}

type JSONError struct {
	ErrorType        string `json:"errorType"`
	ErrorDescription string `json:"errorDescription"`
}

func replyWithError(w http.ResponseWriter, apiError Error, message string) {
	jsonAPIError := JSONError{
		ErrorType:        apiError.Type,
		ErrorDescription: message,
	}

	w.WriteHeader(http.StatusBadRequest)

	if err := json.NewEncoder(w).Encode(jsonAPIError); err != nil {
		message := fmt.Sprintf("Error encoding response as JSON: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
}
