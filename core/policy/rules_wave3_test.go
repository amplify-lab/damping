package policy

import "testing"

// TestMatchCloudAPIRawDelete covers curl/wget calls straight to Railway's
// GraphQL API invoking a resource-deleting mutation — the exact mechanism
// behind the PocketOS incident (2026-04-25): a Cursor session running
// Claude Opus 4.6 found an over-scoped Railway API token in an unrelated
// file and used it to call Railway's API directly with a volumeDelete
// mutation, wiping the production database and its co-located backups in a
// single 9-second call, no confirmation prompt.
func TestMatchCloudAPIRawDelete(t *testing.T) {
	cases := []struct {
		name string
		f    Facts
		want bool
	}{
		{
			"curl POST a volumeDelete mutation to Railway's API (the real PocketOS shape)",
			Facts{
				Command: "curl",
				Args:    []string{"-X", "POST", "https://backboard.railway.app/graphql/v2", "-H", "Authorization: Bearer rw_abc123", "-d", `{"query":"mutation { volumeDelete(volumeId: \"3d2c42fb-...\") }"}`},
				Raw:     `curl -X POST https://backboard.railway.app/graphql/v2 -H "Authorization: Bearer rw_abc123" -d "{\"query\":\"mutation { volumeDelete(volumeId: \\\"3d2c42fb-...\\\") }\"}"`,
			},
			true,
		},
		{
			"curl POST a serviceDelete mutation to Railway's API",
			Facts{
				Command: "curl",
				Args:    []string{"-X", "POST", "https://backboard.railway.app/graphql/v2", "-d", `{"query":"mutation { serviceDelete(id: \"abc\") }"}`},
				Raw:     `curl -X POST https://backboard.railway.app/graphql/v2 -d "{\"query\":\"mutation { serviceDelete(id: \\\"abc\\\") }\"}"`,
			},
			true,
		},
		{
			"wget variant, projectDelete mutation",
			Facts{
				Command: "wget",
				Args:    []string{`--post-data={"query":"mutation { projectDelete(id: \"abc\") }"}`, "https://backboard.railway.app/graphql/v2"},
				Raw:     `wget --post-data='{"query":"mutation { projectDelete(id: \"abc\") }"}' https://backboard.railway.app/graphql/v2`,
			},
			true,
		},
		{
			"curl POST a read-only query to Railway's API, no destructive mutation (safe)",
			Facts{
				Command: "curl",
				Args:    []string{"-X", "POST", "https://backboard.railway.app/graphql/v2", "-d", `{"query":"query { me { name } }"}`},
				Raw:     `curl -X POST https://backboard.railway.app/graphql/v2 -d "{\"query\":\"query { me { name } }\"}"`,
			},
			false,
		},
		{
			"curl mentioning volumeDelete against an unrelated, non-Railway domain (safe)",
			Facts{
				Command: "curl",
				Args:    []string{"-X", "POST", "https://api.internal.example.com/graphql", "-d", `{"query":"mutation { volumeDelete(id: \"abc\") }"}`},
				Raw:     `curl -X POST https://api.internal.example.com/graphql -d "{\"query\":\"mutation { volumeDelete(id: \\\"abc\\\") }\"}"`,
			},
			false,
		},
		{
			"bare GET against Railway's API, no mutation at all (safe)",
			Facts{
				Command: "curl",
				Args:    []string{"https://backboard.railway.app/graphql/v2"},
				Raw:     "curl https://backboard.railway.app/graphql/v2",
			},
			false,
		},
		{
			"curl DELETE a Vercel project (verified real endpoint)",
			Facts{
				Command: "curl",
				Args:    []string{"-X", "DELETE", "https://api.vercel.com/v9/projects/my-app", "-H", "Authorization: Bearer abc"},
				Raw:     `curl -X DELETE https://api.vercel.com/v9/projects/my-app -H "Authorization: Bearer abc"`,
			},
			true,
		},
		{
			"curl DELETE a Netlify site (verified real endpoint)",
			Facts{
				Command: "curl",
				Args:    []string{"--request", "DELETE", "https://api.netlify.com/api/v1/sites/abc123", "-H", "Authorization: Bearer abc"},
				Raw:     `curl --request DELETE https://api.netlify.com/api/v1/sites/abc123 -H "Authorization: Bearer abc"`,
			},
			true,
		},
		{
			"curl DELETE a Render service (verified real endpoint)",
			Facts{
				Command: "curl",
				Args:    []string{"-X", "DELETE", "https://api.render.com/v1/services/srv-abc123"},
				Raw:     "curl -X DELETE https://api.render.com/v1/services/srv-abc123",
			},
			true,
		},
		{
			"curl DELETE a Heroku app (verified real endpoint, the project's own docs example shape)",
			Facts{
				Command: "curl",
				Args:    []string{"-X", "DELETE", "https://api.heroku.com/apps/my-app", "-H", "Authorization: Bearer abc"},
				Raw:     `curl -X DELETE https://api.heroku.com/apps/my-app -H "Authorization: Bearer abc"`,
			},
			true,
		},
		{
			"curl DELETE a DigitalOcean droplet (verified real endpoint)",
			Facts{
				Command: "curl",
				Args:    []string{"-X", "DELETE", "https://api.digitalocean.com/v2/droplets/3164494", "-H", "Authorization: Bearer abc"},
				Raw:     `curl -X DELETE https://api.digitalocean.com/v2/droplets/3164494 -H "Authorization: Bearer abc"`,
			},
			true,
		},
		{
			"wget --method=DELETE a Heroku app",
			Facts{
				Command: "wget",
				Args:    []string{"--method=DELETE", "https://api.heroku.com/apps/my-app"},
				Raw:     "wget --method=DELETE https://api.heroku.com/apps/my-app",
			},
			true,
		},
		{
			"curl GET (no DELETE method) against a Vercel project, read-only (safe)",
			Facts{
				Command: "curl",
				Args:    []string{"https://api.vercel.com/v9/projects/my-app"},
				Raw:     "curl https://api.vercel.com/v9/projects/my-app",
			},
			false,
		},
		{
			"curl -X DELETE against an unrelated, non-provider domain (safe)",
			Facts{
				Command: "curl",
				Args:    []string{"-X", "DELETE", "https://api.internal.example.com/records/123"},
				Raw:     "curl -X DELETE https://api.internal.example.com/records/123",
			},
			false,
		},
		{"unrelated command", Facts{Command: "ls", Args: []string{"-la"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchCloudAPIRawDelete(tc.f, Config{}); got != tc.want {
				t.Errorf("matchCloudAPIRawDelete(%+v) = %v, want %v", tc.f, got, tc.want)
			}
		})
	}
}

// TestMatchCloudAPIRawDelete_DisclosedSubResourceImprecision documents a
// known, deliberate tradeoff (see destructiveCloudAPIHostPattern's own doc
// comment): a DELETE against a narrower sub-resource nested under the same
// path prefix also matches, since the host pattern doesn't anchor the end
// of the URL. This test exists so that behavior is asserted on purpose, not
// accidentally relied upon — if this ever starts failing because someone
// tightened the pattern, that's a deliberate improvement, not a regression.
func TestMatchCloudAPIRawDelete_DisclosedSubResourceImprecision(t *testing.T) {
	f := Facts{
		Command: "curl",
		Args:    []string{"-X", "DELETE", "https://api.vercel.com/v9/projects/my-app/domains/old-example.com"},
		Raw:     "curl -X DELETE https://api.vercel.com/v9/projects/my-app/domains/old-example.com",
	}
	if !matchCloudAPIRawDelete(f, Config{}) {
		t.Error("expected the disclosed sub-resource imprecision to still match (detaching one domain, not the whole project) — see destructiveCloudAPIHostPattern's doc comment")
	}
}
