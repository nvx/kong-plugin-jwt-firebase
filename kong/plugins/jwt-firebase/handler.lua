local cjson = require "cjson.safe"
local http = require "resty.http"
local constants = require "kong.constants"
local local_constants = require "kong.plugins.jwt-firebase.constants"
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local openssl_x509 = require "resty.openssl.x509"

local to_hex = require "resty.string".to_hex
local fmt = string.format
local sha1_bin = ngx.sha1_bin
local kong = kong
local type = type
local pairs = pairs
local ipairs = ipairs
local tostring = tostring
local re_gmatch = ngx.re.gmatch
local re_match = ngx.re.match
local ngx_set_header = ngx.req.set_header
local set_header = kong.service.request.set_header
local clear_header = kong.service.request.clear_header

local shm = ngx.shared.jwt_firebase_keys

local JwtHandler = {}

JwtHandler.PRIORITY = 1201
JwtHandler.VERSION = "1.0.0"

--- Grab a public key from google api by the kid value
-- Grab the public key from https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com 
-- and use a JWT library to verify the signature. Use the value of max-age in the Cache-Control header of the response 
-- from that endpoint to know when to refresh the public keys.
local function grab_public_key_bykid(t_kid)
    kong.log.debug("### grab_public_key_bykid() " .. t_kid)

    local key = shm:get(t_kid)
    if key ~= nil then
        return key
    end

    kong.log.debug("### grab_public_key_bykid() cache miss " .. t_kid)

    local httpc = http:new()
    local res, err = httpc:request_uri("https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com", { method = "GET" })
    if not res then
        kong.log.err('[jwt-firebase] Error getting public keys: ', err)
        kong.response.exit(500)
    end

    if res.status ~= 200 then
        kong.log.err('[jwt-firebase] Error getting public keys, server returned not-200: ', res)
        kong.response.exit(500)
    end

    local keys = cjson.decode(res.body)
    if not keys then
        kong.log.err('[jwt-firebase] Error decoding json keys: ', res.body)
        kong.response.exit(500)
    end

    for k, cert in pairs(keys) do
        local x509cert, err = openssl_x509.new(cert)
        if err ~= nil then
            kong.log.err('[jwt-firebase] Error parsing certificate: ', err)
            kong.response.exit(500)
        end

        local pkey, err = x509cert:get_pubkey()
        if err ~= nil then
            kong.log.err('[jwt-firebase] Error getting pubkey: ', err)
            kong.response.exit(500)
        end

        local keyStr = pkey:tostring()
        shm:set(k, keyStr, 21 * 24 * 60 * 60 * 1000) -- cache keys for 3 weeks

        if k == t_kid then
            key = keyStr
        end
    end

    return key
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
        local iterator, iter_err = re_gmatch(authorization_header, "\\s*[Bb]earer\\s+(.+)")
        if not iterator then
            return nil, iter_err
        end

        local m, err = iterator()
        if err then
            return nil, err
        end

        if m and #m > 0 then
            return m[1]
        end
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
        return kong.response.exit(500, { message = "An unexpected error occurred" })
    end

    local token_type = type(token)
    if token_type ~= "string" then
        if token_type == "nil" then
            return false, { status = 401, message = "Unauthorized" }
        elseif token_type == "table" then
            return false, { status = 401, message = "Multiple tokens provided" }
        else
            return false, { status = 401, message = "Unrecognizable token" }
        end
    end

    -- Decode token
    local jwt, err = jwt_decoder:new(token)
    if err then
        return false, { status = 401, message = "Bad token; " .. tostring(err) }
    end

    -- Verify Header
    -- -- Verify "alg"
    local hd_alg = jwt.header.alg
    kong.log.debug("### header.alg: " .. hd_alg)
    if not hd_alg or hd_alg ~= "RS256" then
        return false, { status = 401, message = "Invalid algorithm" }
    end

    -- Verify Payload
    -- -- Verify "iss"
    local pl_iss = jwt.claims.iss
    kong.log.debug("### payload.iss : " .. pl_iss)
    local conf_iss = "https://securetoken.google.com/" .. conf.project_id
    kong.log.debug("### conf_iss: " .. conf_iss)
    if not pl_iss or pl_iss ~= conf_iss then
        return false, { status = 401, message = "Invalid iss in the header" }
    end
    -- -- Verify the "aud"
    local pl_aud = jwt.claims.aud
    kong.log.debug("### payload.aud: " .. pl_aud)
    kong.log.debug("### conf.project_id: " .. conf.project_id)
    if not pl_aud or pl_aud ~= conf.project_id then
        return false, { status = 401, message = "Invalid aud in the header" }
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
        return false, { status = 401, message = "unknown kid" }
    end

    if not jwt:verify_signature(public_key) then
        return false, { status = 401, message = "Invalid signature" }
    end

    if conf.uid_claim ~= "sub" then
        pl_sub = jwt.claims[conf.uid_claim]
        if not pl_sub then
            return false, { status = 401, message = "missing required uid claim" }
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
        if jwt.claims[claim] ~= nil then
            set_header('X-Firebase-' .. claim:gsub('_', '%-'), jwt.claims[claim])
        else
            clear_header('X-Firebase-' .. claim:gsub('_', '%-'))
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
