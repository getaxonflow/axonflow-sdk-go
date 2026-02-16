// Copyright 2026 AxonFlow
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package axonflow

import (
	"encoding/json"
	"testing"
)

func TestMediaContentJSON_Base64(t *testing.T) {
	media := MediaContent{
		Source:     "base64",
		Base64Data: "iVBORw0KGgoAAAANSUhEUg==",
		MIMEType:   "image/png",
	}

	data, err := json.Marshal(media)
	if err != nil {
		t.Fatalf("Failed to marshal MediaContent: %v", err)
	}

	var decoded MediaContent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal MediaContent: %v", err)
	}

	if decoded.Source != "base64" {
		t.Errorf("Expected source 'base64', got '%s'", decoded.Source)
	}
	if decoded.Base64Data != "iVBORw0KGgoAAAANSUhEUg==" {
		t.Errorf("Expected base64_data 'iVBORw0KGgoAAAANSUhEUg==', got '%s'", decoded.Base64Data)
	}
	if decoded.MIMEType != "image/png" {
		t.Errorf("Expected mime_type 'image/png', got '%s'", decoded.MIMEType)
	}
	if decoded.URL != "" {
		t.Errorf("Expected empty URL for base64 source, got '%s'", decoded.URL)
	}
}

func TestMediaContentJSON_URL(t *testing.T) {
	media := MediaContent{
		Source:   "url",
		URL:      "https://example.com/photo.jpg",
		MIMEType: "image/jpeg",
	}

	data, err := json.Marshal(media)
	if err != nil {
		t.Fatalf("Failed to marshal MediaContent: %v", err)
	}

	var decoded MediaContent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal MediaContent: %v", err)
	}

	if decoded.Source != "url" {
		t.Errorf("Expected source 'url', got '%s'", decoded.Source)
	}
	if decoded.URL != "https://example.com/photo.jpg" {
		t.Errorf("Expected URL 'https://example.com/photo.jpg', got '%s'", decoded.URL)
	}
	if decoded.MIMEType != "image/jpeg" {
		t.Errorf("Expected mime_type 'image/jpeg', got '%s'", decoded.MIMEType)
	}
	if decoded.Base64Data != "" {
		t.Errorf("Expected empty Base64Data for URL source, got '%s'", decoded.Base64Data)
	}
}

func TestMediaContentJSON_OmitsEmptyFields(t *testing.T) {
	media := MediaContent{
		Source:   "url",
		URL:      "https://example.com/photo.jpg",
		MIMEType: "image/jpeg",
	}

	data, err := json.Marshal(media)
	if err != nil {
		t.Fatalf("Failed to marshal MediaContent: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Failed to unmarshal to map: %v", err)
	}

	if _, ok := raw["base64_data"]; ok {
		t.Error("Expected base64_data to be omitted when empty")
	}
}

func TestMediaAnalysisResponseJSON(t *testing.T) {
	jsonStr := `{
		"results": [
			{
				"media_index": 0,
				"sha256_hash": "abc123def456",
				"has_faces": true,
				"face_count": 2,
				"has_biometric_data": false,
				"nsfw_score": 0.01,
				"violence_score": 0.0,
				"content_safe": true,
				"document_type": "receipt",
				"is_sensitive_document": true,
				"has_pii": true,
				"pii_types": ["credit_card", "name"],
				"estimated_cost_usd": 0.003,
				"warnings": ["PII detected in image"]
			},
			{
				"media_index": 1,
				"sha256_hash": "789ghi012jkl",
				"has_faces": false,
				"face_count": 0,
				"has_biometric_data": false,
				"nsfw_score": 0.0,
				"violence_score": 0.0,
				"content_safe": true,
				"is_sensitive_document": false,
				"has_pii": false,
				"estimated_cost_usd": 0.002
			}
		],
		"total_cost_usd": 0.005,
		"analysis_time_ms": 342
	}`

	var resp MediaAnalysisResponse
	if err := json.Unmarshal([]byte(jsonStr), &resp); err != nil {
		t.Fatalf("Failed to unmarshal MediaAnalysisResponse: %v", err)
	}

	if len(resp.Results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(resp.Results))
	}

	const tolerance = 0.0001

	if diff := resp.TotalCostUSD - 0.005; diff < -tolerance || diff > tolerance {
		t.Errorf("Expected total_cost_usd 0.005, got %f", resp.TotalCostUSD)
	}
	if resp.AnalysisTimeMs != 342 {
		t.Errorf("Expected analysis_time_ms 342, got %d", resp.AnalysisTimeMs)
	}

	// Verify first result
	r0 := resp.Results[0]
	if r0.MediaIndex != 0 {
		t.Errorf("Expected media_index 0, got %d", r0.MediaIndex)
	}
	if r0.SHA256Hash != "abc123def456" {
		t.Errorf("Expected sha256_hash 'abc123def456', got '%s'", r0.SHA256Hash)
	}
	if !r0.HasFaces {
		t.Error("Expected has_faces to be true")
	}
	if r0.FaceCount != 2 {
		t.Errorf("Expected face_count 2, got %d", r0.FaceCount)
	}
	if r0.HasBiometricData {
		t.Error("Expected has_biometric_data to be false")
	}
	if !r0.ContentSafe {
		t.Error("Expected content_safe to be true")
	}
	if r0.DocumentType != "receipt" {
		t.Errorf("Expected document_type 'receipt', got '%s'", r0.DocumentType)
	}
	if !r0.IsSensitiveDocument {
		t.Error("Expected is_sensitive_document to be true")
	}
	if !r0.HasPII {
		t.Error("Expected has_pii to be true")
	}
	if len(r0.PIITypes) != 2 {
		t.Fatalf("Expected 2 pii_types, got %d", len(r0.PIITypes))
	}
	if r0.PIITypes[0] != "credit_card" || r0.PIITypes[1] != "name" {
		t.Errorf("Expected pii_types [credit_card, name], got %v", r0.PIITypes)
	}
	if len(r0.Warnings) != 1 {
		t.Fatalf("Expected 1 warning, got %d", len(r0.Warnings))
	}
	if r0.Warnings[0] != "PII detected in image" {
		t.Errorf("Expected warning 'PII detected in image', got '%s'", r0.Warnings[0])
	}

	// Verify second result has no optional fields
	r1 := resp.Results[1]
	if r1.MediaIndex != 1 {
		t.Errorf("Expected media_index 1, got %d", r1.MediaIndex)
	}
	if r1.HasFaces {
		t.Error("Expected has_faces to be false for second result")
	}
	if r1.DocumentType != "" {
		t.Errorf("Expected empty document_type for second result, got '%s'", r1.DocumentType)
	}
	if r1.PIITypes != nil {
		t.Errorf("Expected nil pii_types for second result, got %v", r1.PIITypes)
	}
	if r1.Warnings != nil {
		t.Errorf("Expected nil warnings for second result, got %v", r1.Warnings)
	}
}

func TestClientRequestWithMediaJSON(t *testing.T) {
	req := ClientRequest{
		Query:       "Describe this image",
		UserToken:   "user-123",
		ClientID:    "client-abc",
		RequestType: "chat",
		Context:     map[string]interface{}{"model": "gpt-4o"},
		Media: []MediaContent{
			{
				Source:     "base64",
				Base64Data: "iVBORw0KGgoAAAANSUhEUg==",
				MIMEType:   "image/png",
			},
			{
				Source:   "url",
				URL:      "https://example.com/photo.jpg",
				MIMEType: "image/jpeg",
			},
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal ClientRequest with media: %v", err)
	}

	var decoded ClientRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal ClientRequest: %v", err)
	}

	if decoded.Query != "Describe this image" {
		t.Errorf("Expected query 'Describe this image', got '%s'", decoded.Query)
	}
	if decoded.UserToken != "user-123" {
		t.Errorf("Expected user_token 'user-123', got '%s'", decoded.UserToken)
	}
	if len(decoded.Media) != 2 {
		t.Fatalf("Expected 2 media items, got %d", len(decoded.Media))
	}
	if decoded.Media[0].Source != "base64" {
		t.Errorf("Expected first media source 'base64', got '%s'", decoded.Media[0].Source)
	}
	if decoded.Media[1].Source != "url" {
		t.Errorf("Expected second media source 'url', got '%s'", decoded.Media[1].Source)
	}
}

func TestClientRequestWithoutMediaOmitsField(t *testing.T) {
	req := ClientRequest{
		Query:       "Hello",
		UserToken:   "user-123",
		ClientID:    "client-abc",
		RequestType: "chat",
		Context:     map[string]interface{}{},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal ClientRequest: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Failed to unmarshal to map: %v", err)
	}

	if _, ok := raw["media"]; ok {
		t.Error("Expected media field to be omitted when nil")
	}
}

func TestClientResponseWithMediaAnalysisJSON(t *testing.T) {
	jsonStr := `{
		"success": true,
		"result": "The image shows a receipt from a store.",
		"request_id": "req-456",
		"blocked": false,
		"media_analysis": {
			"results": [
				{
					"media_index": 0,
					"sha256_hash": "abc123",
					"has_faces": false,
					"face_count": 0,
					"has_biometric_data": false,
					"nsfw_score": 0.0,
					"violence_score": 0.0,
					"content_safe": true,
					"document_type": "receipt",
					"is_sensitive_document": true,
					"has_pii": true,
					"pii_types": ["credit_card"],
					"estimated_cost_usd": 0.003,
					"warnings": ["Sensitive document detected"]
				}
			],
			"total_cost_usd": 0.003,
			"analysis_time_ms": 150
		}
	}`

	var resp ClientResponse
	if err := json.Unmarshal([]byte(jsonStr), &resp); err != nil {
		t.Fatalf("Failed to unmarshal ClientResponse with media_analysis: %v", err)
	}

	if !resp.Success {
		t.Error("Expected success to be true")
	}
	if resp.Result != "The image shows a receipt from a store." {
		t.Errorf("Unexpected result: '%s'", resp.Result)
	}
	if resp.MediaAnalysis == nil {
		t.Fatal("Expected media_analysis to be non-nil")
	}
	if len(resp.MediaAnalysis.Results) != 1 {
		t.Fatalf("Expected 1 media analysis result, got %d", len(resp.MediaAnalysis.Results))
	}
	if resp.MediaAnalysis.AnalysisTimeMs != 150 {
		t.Errorf("Expected analysis_time_ms 150, got %d", resp.MediaAnalysis.AnalysisTimeMs)
	}

	r := resp.MediaAnalysis.Results[0]
	if r.DocumentType != "receipt" {
		t.Errorf("Expected document_type 'receipt', got '%s'", r.DocumentType)
	}
	if !r.IsSensitiveDocument {
		t.Error("Expected is_sensitive_document to be true")
	}
	if !r.HasPII {
		t.Error("Expected has_pii to be true")
	}
	if len(r.PIITypes) != 1 || r.PIITypes[0] != "credit_card" {
		t.Errorf("Expected pii_types [credit_card], got %v", r.PIITypes)
	}
}

func TestClientResponseWithoutMediaAnalysisJSON(t *testing.T) {
	jsonStr := `{
		"success": true,
		"result": "Hello world",
		"blocked": false
	}`

	var resp ClientResponse
	if err := json.Unmarshal([]byte(jsonStr), &resp); err != nil {
		t.Fatalf("Failed to unmarshal ClientResponse without media_analysis: %v", err)
	}

	if resp.MediaAnalysis != nil {
		t.Error("Expected media_analysis to be nil when not present")
	}
}
