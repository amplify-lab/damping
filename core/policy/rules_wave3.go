package policy

import "regexp"

// This file holds the 2026-07 wave 3 addition — a single rule, grounded in
// the PocketOS incident, added same-day the incident was found rather than
// bundled into a larger batch, per this project's own "every rule traces to
// a real, verified incident before publishing" convention (see wave 2's own
// doc comment) — kept as its own file rather than appended to
// rules_wave2.go so this rule's diff and reasoning stay traceable to its own
// (later, separate) research pass.

// --- destructive.cloud_api_raw_delete ---
//
// PocketOS (2026-04-25): a Cursor session running Claude Opus 4.6 hit a
// credential mismatch in staging and went looking for a fix on its own — it
// found an API token in an unrelated file, one scoped for managing custom
// domains via Railway's CLI but broad enough to authorize any operation,
// including destructive ones. It used that token to call Railway's API
// directly with a volumeDelete mutation, wiping the production database and
// — since Railway stores volume-level backups in the same volume — every
// backup in the same call. No confirmation prompt, 9 seconds start to
// finish. The Register, 2026-04-27:
// https://www.theregister.com/2026/04/27/cursoropus_agent_snuffs_out_pocketos/
//
// The underlying failure mode isn't Railway-specific: it's an agent using a
// discovered/over-scoped credential to call a cloud/PaaS provider's raw
// management API directly, bypassing the provider's own CLI — and whatever
// confirmation step that CLI might have — entirely. The first version of
// this rule shipped scoped to just Railway; asked directly whether that was
// broad protection or single-incident protection, the honest answer was the
// latter, so this was verified and widened same-day rather than shipped
// narrow — every other host below is checked directly against that
// provider's own API reference, not assumed by analogy to Railway or to
// each other.

// railwayAPIPattern/railwayDestructiveMutationPattern cover Railway
// specifically: its public API is GraphQL-over-POST — a single endpoint,
// backboard.railway.app/graphql/v2 (docs.railway.com/integrations/api), not
// a REST DELETE call — so detecting it means looking at the request body's
// mutation name, not the HTTP method. That's the one host here that can't
// share the REST-DELETE matcher below.
var railwayAPIPattern = regexp.MustCompile(`(?i)https?://backboard\.railway\.(app|com)/graphql`)

// railwayDestructiveMutationPattern matches Railway GraphQL mutations that
// delete a project-level resource — volumes, services, deployments,
// environments, projects — per docs.railway.com/reference/public-api.
// Deliberately narrowed to these resource-destroying mutation names, not
// every mutation Railway's schema exposes: renaming a service or querying
// deployment status through the same endpoint is routine, not this rule's
// concern.
var railwayDestructiveMutationPattern = regexp.MustCompile(`\b(volumeDelete|serviceDelete|serviceInstanceDelete|deploymentRemove|environmentDelete|projectDelete)\b`)

// destructiveCloudAPIHostPattern matches five more cloud/PaaS providers'
// REST API paths for deleting a whole deployed resource — a project, site,
// service, app, or droplet — each verified directly against that provider's
// own API reference:
//
//	Vercel:       DELETE /v9/projects/{idOrName}     docs.vercel.com/docs/rest-api/reference/endpoints/projects/delete-a-project
//	Netlify:      DELETE /api/v1/sites/{site_id}      open-api.netlify.com (deleteSite)
//	Render:       DELETE /v1/services/{serviceId}     api-docs.render.com/reference/delete-service
//	Heroku:       DELETE /apps/{app_id_or_name}        devcenter.heroku.com/articles/platform-api-reference
//	DigitalOcean: DELETE /v2/droplets/{droplet_id}     docs.digitalocean.com/reference/api/reference/#tag/Droplets
//
// All five are genuinely REST (unlike Railway), so one shared pattern plus
// destructiveMethodFlagPattern below covers all of them — deliberately
// anchored to just these five hosts+paths, not a blanket "any curl -X
// DELETE anywhere," which would fire on entirely mundane REST usage having
// nothing to do with cloud infrastructure at all.
//
// Known imprecision, disclosed rather than silently accepted: none of these
// patterns anchor the end of the URL, so a DELETE against a narrower
// sub-resource nested under the same path prefix (e.g. Vercel's own
// /v9/projects/{id}/domains/{domain}, which only detaches one domain, not
// the whole project) also matches. Same tradeoff this file's sibling rules
// already accept for a simple, documented v1 heuristic (see
// matchKubectlBulkDelete's own doc comment) — an unnecessary prompt on a
// minor sub-resource delete is the safer side of this tradeoff to land on,
// not a missed catastrophic one.
var destructiveCloudAPIHostPattern = regexp.MustCompile(`(?i)https?://(api\.vercel\.com/v\d+/projects/|api\.netlify\.com/api/v\d+/sites/|api\.render\.com/v\d+/services/|api\.heroku\.com/apps/|api\.digitalocean\.com/v\d+/droplets/)`)

// destructiveMethodFlagPattern matches a curl/wget flag that sets the
// request method to DELETE: curl's -X DELETE / -XDELETE / --request DELETE
// / --request=DELETE, or wget's --method=DELETE / --method DELETE (wget has
// no -X flag at all — its method flag is spelled differently).
var destructiveMethodFlagPattern = regexp.MustCompile(`(?i)(-X\s*DELETE\b|--request[\s=]DELETE\b|--method[\s=]DELETE\b)`)

func matchCloudAPIRawDelete(f Facts, _ Config) bool {
	if f.Command != "curl" && f.Command != "wget" {
		return false
	}
	if destructiveCloudAPIHostPattern.MatchString(f.Raw) && destructiveMethodFlagPattern.MatchString(f.Raw) {
		return true
	}
	// Railway's own API is GraphQL-over-POST, not REST — see this file's top
	// doc comment for why it needs its own separate check.
	return railwayAPIPattern.MatchString(f.Raw) && railwayDestructiveMutationPattern.MatchString(f.Raw)
}
