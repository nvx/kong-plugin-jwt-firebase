local typedefs = require "kong.db.schema.typedefs"

return {
    name = "jwt-firebase",
    fields = {
        { consumer = typedefs.no_consumer },
        { protocols = typedefs.protocols_http },
        { config = {
            type = "record",
            fields = {
                { uri_param_names = {
                    type = "set",
                    elements = { type = "string" },
                    default = {},
                }, },
                { cookie_names = {
                    type = "set",
                    elements = { type = "string" },
                    default = {}
                }, },
                { uid_from = { type = "string", default = "claim", one_of = { "claim", "identities", "sign_in_attributes" } }, },
                { uid_field = { type = "string", default = "sub" }, },
                { uid_inreq_header = { type = "boolean", default = false }, },
                { returned_claims = { type = "array", default = { }, elements = { type = "string" } } },
                { returned_sign_in_attributes = { type = "array", default = { }, elements = { type = "string" } } },
                { hide_credentials = { type = "boolean", default = true } },
                { claims_to_verify = {
                    type = "set",
                    default = { "exp" },
                    elements = {
                        type = "string",
                        one_of = { "exp", "nbf" },
                    },
                }, },
                { maximum_expiration = {
                    type = "number",
                    default = 0,
                    between = { 0, 31536000 },
                }, },
                { project_id = { type = "string", required = true }, },
            },
        }, },
    },
}
