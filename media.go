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
	Source     string `json:"source"`               // "base64" or "url"
	Base64Data string `json:"base64_data,omitempty"` // Base64-encoded image data
	URL        string `json:"url,omitempty"`         // Image URL
	MIMEType   string `json:"mime_type"`             // e.g., "image/jpeg"
}

// MediaAnalysisResponse contains aggregated media analysis results.
type MediaAnalysisResponse struct {
	Results        []MediaAnalysisResult `json:"results"`
	TotalCostUSD   float64              `json:"total_cost_usd"`
	AnalysisTimeMs int64                `json:"analysis_time_ms"`
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
	ExtractedText       string   `json:"extracted_text,omitempty"`
	EstimatedCostUSD    float64  `json:"estimated_cost_usd"`
	Warnings            []string `json:"warnings,omitempty"`
}
