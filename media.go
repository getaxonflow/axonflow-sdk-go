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

// MediaContent represents a media item (image) to include with a request.
type MediaContent struct {
	Source     string `json:"source"`                // "base64" or "url"
	Base64Data string `json:"base64_data,omitempty"` // Base64-encoded image data
	URL        string `json:"url,omitempty"`         // Image URL
	MIMEType   string `json:"mime_type"`             // e.g., "image/jpeg"
}

// MediaAnalysisResponse contains aggregated media analysis results.
type MediaAnalysisResponse struct {
	Results        []MediaAnalysisResult `json:"results"`
	TotalCostUSD   float64               `json:"total_cost_usd"`
	AnalysisTimeMs int64                 `json:"analysis_time_ms"`
}

// MediaAnalysisResult contains analysis results for a single media item.
type MediaAnalysisResult struct {
	MediaIndex          int      `json:"media_index"`
	SHA256Hash          string   `json:"sha256_hash"`
	HasFaces            bool     `json:"has_faces"`
	FaceCount           int      `json:"face_count"`
	HasBiometricData    bool     `json:"has_biometric_data"`
	NSFWScore           float64  `json:"nsfw_score"`
	ViolenceScore       float64  `json:"violence_score"`
	ContentSafe         bool     `json:"content_safe"`
	DocumentType        string   `json:"document_type,omitempty"`
	IsSensitiveDocument bool     `json:"is_sensitive_document"`
	HasPII              bool     `json:"has_pii"`
	PIITypes            []string `json:"pii_types,omitempty"`
	HasExtractedText    bool     `json:"has_extracted_text"`
	ExtractedTextLength int      `json:"extracted_text_length"`
	EstimatedCostUSD    float64  `json:"estimated_cost_usd"`
	Warnings            []string `json:"warnings,omitempty"`
}

// MediaGovernanceConfig represents per-tenant media governance configuration.
type MediaGovernanceConfig struct {
	TenantID         string   `json:"tenant_id"`
	Enabled          bool     `json:"enabled"`
	AllowedAnalyzers []string `json:"allowed_analyzers,omitempty"`
	UpdatedAt        string   `json:"updated_at"`
	UpdatedBy        string   `json:"updated_by,omitempty"`
}

// MediaGovernanceStatus represents the feature availability status.
type MediaGovernanceStatus struct {
	Available        bool   `json:"available"`
	EnabledByDefault bool   `json:"enabled_by_default"`
	PerTenantControl bool   `json:"per_tenant_control"`
	Tier             string `json:"tier"`
}

// UpdateMediaGovernanceConfigRequest is the request body for updating config.
type UpdateMediaGovernanceConfigRequest struct {
	Enabled          *bool     `json:"enabled,omitempty"`
	AllowedAnalyzers *[]string `json:"allowed_analyzers,omitempty"`
}
