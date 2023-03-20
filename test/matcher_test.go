package main

import (
	"testing"
	matchers "pkg/matchers"
	"github.com/PuerkitoBio/goquery"
)

type RequestParams struct {
    Method string
    Paths  []string
}

func TestGet(t *testing.T) {
	type args struct {
		url    string
		params *matchers.RequestParams
	}

	tests := []struct {
		name    string
		args    args
		want    *goquery.Document
		want1   int
		wantErr bool
	}{
		{
			name: "Matcher Successful Response",
			args: args{
				url: "https://payments.insuredyou.ca",
				params: &matchers.RequestParams{
					Method: "GET",
					Paths:  []string{"/.git/config", "/.git/HEAD"},
				},
			},
			want:    &goquery.Document{},
			want1:   200,
			wantErr: false,
		},
		{
			name: "Matcher successful response",
			args: args{
				url: "https://pharmacy.fekrasoft.org",
				params: &matchers.RequestParams{
					Method: "GET",
					Paths:  []string{"/.git/config", "/.git/HEAD"},
				},
			},
			want:    &goquery.Document{},
			want1:   200,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			document, statusCode, err := matchers.Get(tt.args.url, tt.args.params)

			if err != nil {
				t.Logf("Error %s", err)
				return
			}
	
			t.Logf("Response Status Code: %d\n", statusCode)

			// Display body
			t.Logf("Document Body Response")
			t.Logf(document.Text())
		})
	}
}

