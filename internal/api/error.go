package api

import (
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	MissingPostParameter = "missing_post_parameter"
	UserIDNotSupplied    = "user_id_not_supplied"
	InvalidPublicKey     = "invalid_public_key"
	ConfigNotFound       = "config_not_found"
	UserAlreadyEnabled   = "user_already_enabled"
	UserAlreadyDisabled  = "user_already_disabled"
)

type Error struct {
	ErrorType        string `json:"errorType"`
	ErrorDescription string `json:"errorDescription"`
}

func replyWithError(w http.ResponseWriter, errorType string, message string) {
	apiError := Error{
		ErrorType:        errorType,
		ErrorDescription: message,
	}

	w.WriteHeader(http.StatusBadRequest)

	if err := json.NewEncoder(w).Encode(apiError); err != nil {
		message := fmt.Sprintf("Error encoding response as JSON: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
}
