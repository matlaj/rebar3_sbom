-define(APP, "rebar3_sbom").
-define(DEFAULT_OUTPUT, "./bom.[xml|json]").
-define(DEFAULT_VERSION, 1).
-define(PROVIDER, sbom).
-define(DEPS, [lock]).


-record(component, {
    type = "application",
    bom_ref :: string(),
    authors :: [#{name := string()}],
    name :: string(),
    version :: string(),
    description :: string(),
    hashes :: [#{alg := string(), hash := string()}],
    licenses :: [#{name := string()} | #{id := string()}],
    externalReferences :: [#{type := string(), url := string()}],
    purl :: string()
}).

-record(metadata, {
    timestamp :: string(),
    component :: #component{},
    tools = [] :: [string()]
}).

-record(dependency, {
    ref :: string(),
    dependencies = [] :: [#dependency{}]
}).

-record(sbom, {
    format = "CycloneDX" :: string(),
    version = ?DEFAULT_VERSION :: integer(),
    serial :: string(),
    metadata :: #metadata{},
    components :: [#component{}],
    dependencies :: [#dependency{}]
}).
