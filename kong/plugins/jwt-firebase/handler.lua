local cjson = require "cjson.safe"
local http = require "resty.http"
local constants = require "kong.constants"
local local_constants = require "kong.plugins.jwt-firebase.constants"
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"

local to_hex = require "resty.string".to_hex
local fmt = string.format
local sha1_bin = ngx.sha1_bin
local kong = kong
local type = type
local pairs = pairs
local ipairs = ipairs
local tostring = tostring
local re_match = ngx.re.match
local ngx_set_header = ngx.req.set_header
local set_header = kong.service.request.set_header
local clear_header = kong.service.request.clear_header

local shm = ngx.shared.jwt_firebase_keys

local JwtHandler = {}

JwtHandler.PRIORITY = 1201
JwtHandler.VERSION = "1.2.0"

local function fetch_keys()
    kong.log.debug("### fetch_keys()")

    local httpc = http:new()
    local res, err = httpc:request_uri("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com", { method = "GET" })
    if not res then
        kong.log.err('Error getting public keys: ', err)
        kong.response.exit(500)
    end

    if res.status ~= 200 then
        kong.log.err('Error getting public keys, server returned not-200: ', res)
        kong.response.exit(500)
    end

    local cache_duration = 60 * 60 -- cache for 1 hour (in seconds) if we fail to parse the Cache-Control header
    local cache_control_header = res.headers['cache-control']
    local m, err = re_match(cache_control_header, "(^|,\\s*)max-age=([0-9]+)")
    if m then
        cache_duration = tonumber(m[2])
    else
        kong.log.debug("### fetch_keys() failed to parse cache-control header")
    end

    shm:set("jwk-all", res.body, cache_duration)

    return res.body
end

--- Grab a public key from google api by the kid value
-- Grab the public key from https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com 
-- and use a JWT library to verify the signature. Use the value of max-age in the Cache-Control header of the response 
-- from that endpoint to know when to refresh the public keys.
local function grab_public_key_bykid(t_kid)
    kong.log.debug("### grab_public_key_bykid() " .. t_kid)

    local key = shm:get("jwk-" .. t_kid)
    if key then
        return key
    end

    -- we cache the jwk endpoint too to avoid making a request if an unknown kid is specified
    local json_keys = shm:get("jwk-all")
    if json_keys == nil then
        json_keys = fetch_keys()
    end

    local keys = cjson.decode(json_keys)
    if not keys then
        kong.log.err('Error decoding json keys: ', res.body)
        kong.response.exit(500)
    end

    for _, jwk in pairs(keys.keys) do
        if jwk.kid == t_kid then
            local encoded = cjson.encode(jwk)
            shm:set("jwk-" .. t_kid, encoded, 24 * 60 * 60 * 1000) -- cache the encoded key itself too for faster access
            return encoded
        end
    end
end

--- Retrieve a JWT in a request.
-- Checks for the JWT in URI parameters, then in cookies, and finally
-- in the `Authorization` header.
-- @param request ngx request object
-- @param conf Plugin configuration
-- @return token JWT token contained in request (can be a table) or nil
-- @return err
local function retrieve_token(conf)
    local args = kong.request.get_query()
    for _, v in ipairs(conf.uri_param_names) do
        if args[v] then
            return args[v]
        end
    end

    local var = ngx.var
    for _, v in ipairs(conf.cookie_names) do
        local cookie = var["cookie_" .. v]
        if cookie and cookie ~= "" then
            return cookie
        end
    end

    local authorization_header = kong.request.get_header("authorization")
    if authorization_header then
        local m, err = re_match(authorization_header, "\\s*[Bb]earer\\s+(.+)")
        if not m then
            return authorization_header
        end
        return m[1]
    end
end

local function set_consumer(consumer, credential)
    if consumer ~= nil or credential ~= nil then
        kong.client.authenticate(consumer, credential)
    end

    if consumer and consumer.id then
        set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
    else
        clear_header(constants.HEADERS.CONSUMER_ID)
    end

    if consumer and consumer.custom_id then
        set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
    else
        clear_header(constants.HEADERS.CONSUMER_CUSTOM_ID)
    end

    if consumer and consumer.username then
        set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
    else
        clear_header(constants.HEADERS.CONSUMER_USERNAME)
    end

    if credential and credential.username then
        set_header(constants.HEADERS.CREDENTIAL_IDENTIFIER, credential.username)
    else
        clear_header(constants.HEADERS.CREDENTIAL_IDENTIFIER)
        clear_header(constants.HEADERS.CREDENTIAL_USERNAME)
    end

    if credential then
        clear_header(constants.HEADERS.ANONYMOUS)
    else
        set_header(constants.HEADERS.ANONYMOUS, true)
    end
end

local function cache_key(conf, username)
    local hash = to_hex(sha1_bin(fmt("%s:%s:%s",
            conf.introspection_url,
            conf.client_id,
            username)))

    return "jwt_firebase_cache:" .. hash
end

--- do_authentication is to verify JWT firebase token
---   ref to: https://firebase.google.com/docs/auth/admin/verify-id-tokens
local function do_authentication(conf)
    local token, err = retrieve_token(conf)
    if err then
        kong.log.err(err)
        return kong.response.exit(500, { message = "an unexpected error occurred" })
    end

    local token_type = type(token)
    if token_type ~= "string" then
        if token_type == "nil" then
            return false, { status = 401, message = "unauthorized" }
        elseif token_type == "table" then
            return false, { status = 401, message = "multiple tokens provided" }
        else
            return false, { status = 401, message = "unrecognizable token" }
        end
    end

    -- Decode token
    local jwt, err = jwt_decoder:new(token)
    if err then
        return false, { status = 401, message = "bad token; " .. tostring(err) }
    end

    -- Verify Header
    -- -- Verify "alg"
    local hd_alg = jwt.header.alg
    kong.log.debug("### header.alg: " .. hd_alg)
    if not hd_alg or hd_alg ~= "RS256" then
        return false, { status = 401, message = "invalid algorithm" }
    end

    -- Verify Payload
    -- -- Verify "iss"
    local pl_iss = jwt.claims.iss
    kong.log.debug("### payload.iss : " .. pl_iss)
    local conf_iss = "https://securetoken.google.com/" .. conf.project_id
    kong.log.debug("### conf_iss: " .. conf_iss)
    if not pl_iss or pl_iss ~= conf_iss then
        return false, { status = 401, message = "invalid iss in the header" }
    end
    -- -- Verify the "aud"
    local pl_aud = jwt.claims.aud
    kong.log.debug("### payload.aud: " .. pl_aud)
    kong.log.debug("### conf.project_id: " .. conf.project_id)
    if not pl_aud or pl_aud ~= conf.project_id then
        return false, { status = 401, message = "invalid aud in the header" }
    end
    -- -- Verify the "exp"
    kong.log.debug("### Checking exp ... ")
    local ok_claims, errors = jwt:verify_registered_claims(conf.claims_to_verify)
    if not ok_claims then
        return false, { status = 401, errors = errors }
    end
    -- -- Verify the "exp" with "maximum_expiration" value
    kong.log.debug("### Checking additional maximum expiration ...")
    if conf.maximum_expiration ~= nil and conf.maximum_expiration > 0 then
        local ok, errors = jwt:check_maximum_expiration(conf.maximum_expiration)
        if not ok then
            return false, { status = 401, errors = errors }
        end
    end

    -- -- Verify the "sub" must be non-empty
    local pl_sub = jwt.claims.sub
    kong.log.debug("### payload.sub: " .. pl_sub)
    if not pl_sub then
        return false, { status = 401, message = "the sub must be non-empty" }
    end

    -- Finally -- Verify the signature
    -- Finally, ensure that the ID token was signed by the private key corresponding to the token's kid claim.
    -- Grab the public key from https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com
    -- and use a JWT library to verify the signature. Use the value of max-age in the Cache-Control header of the response
    -- from that endpoint to know when to refresh the public keys.
    -- Now verify the JWT signature
    local public_key = grab_public_key_bykid(jwt.header.kid)
    if public_key == nil then
        return false, { status = 401, message = "unknown kid: " .. jwt.header.kid }
    end

    if not jwt:verify_signature(public_key) then
        return false, { status = 401, message = "invalid signature" }
    end

    if conf.uid_from == "claim" then
        if conf.uid_field ~= "sub" then
            pl_sub = jwt.claims[conf.uid_field]
            if not pl_sub then
                return false, { status = 401, message = "missing required uid claim" }
            end
        end
    elseif conf.uid_from == "identities" then
        pl_sub = nil
        -- assume we only have one value
        if jwt.claims.firebase ~= nil and jwt.claims.firebase.identities ~= nil and
                jwt.claims.firebase.identities[conf.uid_field] ~= nil and
                #jwt.claims.firebase.identities[conf.uid_field] == 1 then
            pl_sub = jwt.claims.firebase.identities[conf.uid_field][1]
        end
        if not pl_sub then
            return false, { status = 401, message = "missing required uid identity" }
        end
    elseif conf.uid_from == "sign_in_attributes" then
        pl_sub = nil
        if jwt.claims.firebase ~= nil and jwt.claims.firebase.sign_in_attributes ~= nil then
            pl_sub = jwt.claims.firebase.sign_in_attributes[conf.uid_field]
        end
        if not pl_sub then
            return false, { status = 401, message = "missing required uid attribute" }
        end
    end

    if conf.hide_credentials then
        clear_header('Authorization')
    end

    -- -- Pud user-id into request header
    if conf.uid_inreq_header then
        ngx_set_header(local_constants.HEADERS.TOKEN_USER_ID, pl_sub)
        kong.log.debug("### Set " .. local_constants.HEADERS.TOKEN_USER_ID .. ": " .. pl_sub .. " in the request header")
    end

    for _, claim in pairs(conf.returned_claims) do
        local header_name = local_constants.HEADERS.CLAIM_PREFIX .. claim:gsub('_', '%-')
        if jwt.claims[claim] ~= nil then
            set_header(header_name, jwt.claims[claim])
        else
            clear_header(header_name)
        end
    end

    for _, claim in pairs(conf.returned_sign_in_attributes) do
        local header_name = local_constants.HEADERS.CLAIM_PREFIX .. claim:gsub('_', '%-')
        if jwt.claims.firebase ~= nil and jwt.claims.firebase.sign_in_attributes[claim] ~= nil then
            set_header(header_name, jwt.claims.firebase.sign_in_attributes[claim])
        else
            clear_header(header_name)
        end
    end

    local credential = {
        id = cache_key(conf, pl_sub),
        username = pl_sub,
    }

    set_consumer(nil, credential)

    return true
end

function JwtHandler:access(conf)
    local ok, err = do_authentication(conf)
    if not ok then
        return kong.response.exit(err.status, err.errors or { message = err.message })
    end
end

return JwtHandler
