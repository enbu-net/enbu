package main

import (
	"log/slog"

	"github.com/enbu-net/enbu/desktop"
	"github.com/enbu-net/enbu/internal/apphost"
	"github.com/enbu-net/enbu/pkg/apperr"
)

type BindingResponse struct {
	Data  any             `json:"data"`
	Error *apperr.Payload `json:"error,omitempty"`
}

// DesktopService is deliberately finite. No method accepts or returns secret
// payload bytes, arbitrary executable actions, local paths selected by the
// webview, or storage/registry capabilities.
type DesktopService struct{ service *desktop.Service }

func bindingResult[T any](data T, err error) BindingResponse {
	if err == nil {
		return BindingResponse{Data: data}
	}
	normalized := apphost.NormalizeError(err)
	payload := apperr.PayloadOf(normalized)
	if payload.Code == apperr.CodeInternal || payload.Code == apperr.CodeUnavailable {
		slog.Error("desktop operation failed", "err", normalized)
	}
	return BindingResponse{Error: &payload}
}

func bindingError(err error) BindingResponse { return bindingResult[any](nil, err) }

func (service *DesktopService) BrowseWorkspace() BindingResponse {
	value, err := service.service.BrowseWorkspace()
	return bindingResult(value, err)
}

func (service *DesktopService) Snapshot(sessionID string) BindingResponse {
	value, err := service.service.Snapshot(sessionID)
	return bindingResult(value, err)
}

func (service *DesktopService) StartImportFile(sessionID, name, format, mediaType string) BindingResponse {
	value, err := service.service.StartImportFile(sessionID, name, format, mediaType)
	return bindingResult(value, err)
}

func (service *DesktopService) StartMaterialize(sessionID, commitID, resourceID, payload, format string) BindingResponse {
	value, err := service.service.StartMaterialize(sessionID, commitID, resourceID, payload, format)
	return bindingResult(value, err)
}

func (service *DesktopService) ListResources(sessionID, commitID, cursor string) BindingResponse {
	value, err := service.service.ListResources(sessionID, commitID, cursor)
	return bindingResult(value, err)
}

func (service *DesktopService) ListCommits(sessionID string, frontier []string, cursor string) BindingResponse {
	value, err := service.service.ListCommits(sessionID, frontier, cursor)
	return bindingResult(value, err)
}

func (service *DesktopService) PollOperation(sessionID, operationID string, cursor uint64) BindingResponse {
	value, err := service.service.PollOperation(sessionID, operationID, cursor)
	return bindingResult(value, err)
}

func (service *DesktopService) CancelOperation(sessionID, operationID string) BindingResponse {
	return bindingError(service.service.CancelOperation(sessionID, operationID))
}

func (service *DesktopService) CloseWorkspace(sessionID string) BindingResponse {
	return bindingError(service.service.CloseWorkspace(sessionID))
}

func (service *DesktopService) GetAppVersion() BindingResponse {
	return bindingResult(service.service.GetAppVersion(), nil)
}
