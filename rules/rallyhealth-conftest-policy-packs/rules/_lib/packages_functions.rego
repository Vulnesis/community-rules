# Adapted from https://github.com/rallyhealth/conftest-policy-packs
# Helper package — not a rule (no metadata/findings).

package vulnesis.rallyhealth.packages_utils

import rego.v1

is_package_json(path) if endswith(lower(path), "package.json")

parse_pkg(content) := obj if {
	obj := json.unmarshal(content)
}
