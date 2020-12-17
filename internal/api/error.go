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
)

type Error struct {
	Name string
}

type JSONError struct {
	ErrorType        string `json:"errorType"`
	ErrorDescription string `json:"errorDescription"`
}

func replyWithError(w http.ResponseWriter, error Error, message string) {
	apiError := JSONError{
		ErrorType:        error.Name,
		ErrorDescription: message,
	}

	w.WriteHeader(http.StatusBadRequest)

	if err := json.NewEncoder(w).Encode(apiError); err != nil {
		message := fmt.Sprintf("Error encoding response as JSON: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
}
