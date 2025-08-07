package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	testCases := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "Valid API Key",
			headers:       http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expectedKey:   "my-secret-key",
			expectedError: nil,
		},
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Malformed Header - Missing 'ApiKey' prefix",
			headers:       http.Header{"Authorization": []string{"Bearer my-token"}},
			expectedKey:   "",
			expectedError: ErrMalformedHeader,
		},
		{
			name:          "Malformed Header - Missing key",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectedError: ErrMalformedHeader,
		},
		{
			name:          "Malformed Header - Empty key",
			headers:       http.Header{"Authorization": []string{"ApiKey "}},
			expectedKey:   "",
			expectedError: ErrMalformedHeader,
		},
		{
			name:          "Malformed Header - Multiple spaces",
			headers:       http.Header{"Authorization": []string{"ApiKey  my-key"}},
			expectedKey:   "",
			expectedError: ErrMalformedHeader,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)

			if key != tc.expectedKey {
				t.Errorf("expected key: %s, got: %s", tc.expectedKey, key)
			}

			if tc.expectedError == nil {
				if err != nil {
					t.Errorf("expected no error, but got: %v", err)
				}
				return
			}

			t.Log(key, err)

			if err == nil {
				t.Errorf("expected error: %v, but got no error", tc.expectedError)
				return
			}

			if err == ErrNoAuthHeaderIncluded {
				if tc.expectedError != ErrNoAuthHeaderIncluded {
					t.Errorf("expected error: %v, but got: %v", tc.expectedError, err)
				}
				return
			}

			if err.Error() != tc.expectedError.Error() {
				t.Errorf("expected error message: %q, but got: %q", tc.expectedError.Error(), err.Error())
			}
		})
	}
}
