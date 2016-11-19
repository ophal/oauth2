local _M = {
  resources = nil,
}
ophal.modules.oauth2 = _M

local seawolf = require 'seawolf'.__build('contrib', 'text')
local config = settings.oauth2
local xtable, time, base = seawolf.contrib.seawolf_table, os.time, base
local explode, env, tonumber = seawolf.text.explode, env, tonumber
local empty, goto, site = seawolf.variable.empty, goto, settings.site
local header, route_arg, sleep = header, route_arg, socket.sleep
local request_uri, escape = request_uri, socket.url.escape
local _SESSION = _SESSION
local db_query, user_mod

function _M.init()
  db_query = env.db_query
  user_mod = ophal.modules.user

  -- Oauth2 session fingerprint
  if _SESSION and _SESSION.oauth2 == nil then
    _SESSION.oauth2 = {}
  end
end

function _M.cron()
  db_query('DELETE FROM oauth2_google_nonce WHERE ? > created + ?', time(), config.google.nonce_ttl or 2*60)
end

function _M.route()
  local items = {}

  items['oauth2/google'] = {
    page_callback = 'google_callback',
    format = 'json',
  }
  items['oauth2/facebook'] = {
    page_callback = 'facebook_callback',
    format = 'json',
  }

  return items
end

function _M.google_valid_nonce(nonce)
  local rs = db_query('SELECT COUNT(*) total FROM oauth2_google_nonce WHERE id = ? AND ? <= created + ?', nonce, time(), config.google.nonce_ttl or 2*60)
  local count = rs:fetch(true)
  if count then
    return tonumber(count.total) > 0
  end
end

function _M.google_create_authcodes(entity)
  local rs = db_query('INSERT INTO oauth2_google_token(id, resource, access_token, refresh_token, user_id, created, changed, ttl) VALUES(?, ?, ?, ?, ?, ?, ?, ?)', entity.id, entity.resource, entity.access_token, entity.refresh_token, entity.user_id, time(), time(), entity.ttl)
end

function _M.google_load_authcodes(id)
  local rs = db_query('SELECT * FROM oauth2_google_token WHERE id = ?', id)
  return rs:fetch(true)
end

function _M.google_update_authcodes(entity)
  local rs = db_query('UPDATE oauth2_google_token SET access_token = ?, changed = ?, ttl = ? WHERE id = ?', entity.access_token, time(), entity.ttl, entity.id)
end

function _M.google_get_resource(id)
  if empty(_M.resources) then
    _M.resources = module_invoke_all 'oauth2_resource'
  end

  if not empty(_M.resources) then
    return _M.resources[id]
  end
end

function _M.google_get_authcodes(code)
  local json = require 'dkjson'
  local https = require 'ssl.https'
  local ltn12 = require 'ltn12'
  local body = _M.build_params{
    code = code,
    client_id = config.google.client_id,
    client_secret = config.google.client_secret,
    redirect_uri = ('%s://%s/oauth2/callback'):format(site.scheme or 'http', _SERVER 'SERVER_NAME'),
    grant_type = 'authorization_code',
  }
  local response = {}
  local request = {
    url = 'https://www.googleapis.com/oauth2/v3/token',
    method = 'POST',
    headers = {
      ['content-length'] = #body,
      ['content-type'] = 'application/x-www-form-urlencoded',
    },
    source = ltn12.source.string(body),
    sink = ltn12.sink.table(response),
  }
  local s, c, h, hs = https.request(request)

  if c == 200 then
    local response = xtable(response):concat()
    return json.decode(response)
  end
end

function _M.google_callback()
  local state = explode('|', _GET.state)
  local resource_id = state[1]
  local nonce = state[2]

  local resource = _M.google_get_resource(resource_id)

  if _M.google_valid_nonce(nonce) and not empty(resource) then
    local res = _M.google_get_authcodes(_GET.code)
    res.id = _GET.code
    res.resource = resource_id
    res.user_id = 1
    res.ttl = res.expires_in
    _M.google_create_authcodes(res)
  end

  goto(resource.path)

  return ''
end

function _M.build_params(params)
  local output = xtable()
  for k, v in pairs(params) do
    output:append(k .. '=' .. escape(v))
  end
  return output:concat '&'
end

function _M.google_get_nonce(resource)
  local uuid = require 'uuid'
  local nonce = uuid.new()
  local rs, err = db_query('INSERT INTO oauth2_google_nonce(id, created) VALUES(?, ?)', nonce, time())
  return resource .. '|' .. nonce
end

function _M.google_refresh_authcodes(id)
  local token = _M.google_load_authcodes(id)
  if not empty(token) then
    local json = require 'dkjson'
    local https = require 'ssl.https'
    local ltn12 = require 'ltn12'
    local body = _M.build_params{
      refresh_token = token.refresh_token,
      client_id = config.google.client_id,
      client_secret = config.google.client_secret,
      grant_type = 'refresh_token',
    }
    local response = {}
    local request = {
      url = 'https://www.googleapis.com/oauth2/v3/token',
      method = 'POST',
      headers = {
        ['content-length'] = #body,
        ['content-type'] = 'application/x-www-form-urlencoded',
      },
      source = ltn12.source.string(body),
      sink = ltn12.sink.table(response),
    }
    local s, c, h, hs = https.request(request)
    if c == 200 then
      local response = xtable(response):concat()
      return json.decode(response)
    end
  end
end

function _M.google_get_token(resource, user_id)
  local rs, err = db_query('SELECT id, access_token, refresh_token, changed, ttl FROM oauth2_google_token WHERE resource = ? AND user_id = ? ORDER BY changed DESC', resource, user_id)
  local token = rs:fetch(true)
  if not empty(token) then
    if token.changed + token.ttl > time() then
      return token.access_token
    else
      res = _M.google_refresh_authcodes(token.id)
      if res then
        res.id = token.id
        res.ttl = res.expires_in
        _M.google_update_authcodes(res)
        return res.access_token
      end
    end
  end
end

function _M.facebook_api_path(path)
  return 'https://graph.facebook.com/' .. (config.facebook.api_version or 'v2.3') .. (path or '')
end

--[[ Given an approval code from Facebook, return an access token and related.

  The approval code is generated by Facebook when a user grants access to our
  site application to use their data. We use this approval code to get an
  access token from Facebook. The access token usually is valid for about
  15 minutes, allowing us to pull as much information as we want about the
  user.

  @param string $code
    An approval code from Facebook. Usually pulled from the ?code GET parameter
    after a user has approved our application's access to their information.

  @param string $action_name
    The action is the directory name underneath the "fboauth" path. This value
    must be the same between the page originally provided to Facebook as the
    "redirect" URL and when requesting an access token.

  @return string
    An access token that can be used in REST queries against Facebook's Graph
    API, which will provide us with info about the Facebook user.
]]
function _M.facebook_get_authcodes(code, app_id, app_secret)
  local json = require 'dkjson'
  local https = require 'ssl.https'
  local ltn12 = require 'ltn12'
  local authentication_result = {}
  local query, token_url, authentication_values

  -- Use the default App ID and App Secret if not specified.
  app_id = app_id or config.facebook.app_id
  app_secret = app_secret or config.facebook.app_secret

  -- Note that the "code" provided by Facebook is a hash based on the client_id,
  -- client_secret, and redirect_url. All of these things must be IDENTICAL to
  -- the same values that were passed to Facebook in the approval request. See
  -- the fboauth_link_properties function.
  query = {
    client_id = app_id,
    client_secret = app_secret,
    --~ auth_type = 'request',
    redirect_uri = url('oauth2/facebook/', {absolute = true}),
    code = code,
  }

  token_url = _M.facebook_api_path('/oauth/access_token') .. '?' .. _M.build_params(query)

  for i = 1, 5 do
    local response = xtable()
    local r, c, h, s = https.request{
      url = token_url,
      method = 'GET',
      sink = ltn12.sink.table(response),
    }
    authentication_result.res 	  = r
    authentication_result.code 	  = c
    authentication_result.headers = h
    authentication_result.status  = s
    authentication_result.data    = response:concat()

    if authentication_result.code == 200 then
      break
    end
    -- Facebook access code generation seems to take a lot of time. That's why we have to wait
    -- some seconds before the code can be acquired.
    sleep(1)
  end

  if 200 ~= authentication_result.code then
    if authentication_result.data then
      error(authentication_result.data)
    elseif authentication_result.error then
      error(authentication_result.error)
    else
      error 'Unknown error.'
    end
  else
    return json.decode(authentication_result.data)
  end
end

--[[ Execute a Graph API query through Facebook.

  @see http://developers.facebook.com/docs/reference/api/
]]
function _M.facebook_graph_query(id, access_token, params, method)
  params = params or {}
  method = method or 'GET'

  local json = require 'dkjson'
  local https = require 'ssl.https'
  local ltn12 = require 'ltn12'
  local graph_result = {}
  local graph_url, post_data, output

  if access_token then
    params.access_token = access_token
  end

  if method == 'GET' or method == 'DELETE' then
    graph_url = _M.facebook_api_path('/' .. id) .. '?' .. _M.build_params(params)
    local response = xtable()
    local r, c, h, s = https.request{
      url = graph_url,
      method = 'GET',
      sink = ltn12.sink.table(response),
    }
    graph_result.res 	 = r
    graph_result.code 	 = c
    graph_result.headers = h
    graph_result.status  = s
    graph_result.data    = response:concat()
  elseif method == 'POST' then
    graph_url = _M.facebook_api_path('/' .. id)
    post_data = _M.build_params(params)
    local response = xtable()
    local r, c, h, s = https.request{
      url = graph_url,
      method = 'GET',
      headers = {
        ['content-length'] = #body,
        ['content-type'] = 'application/x-www-form-urlencoded',
      },
      source = ltn12.source.string(body),
      sink = ltn12.sink.table(response),
    }
    graph_result.res 	 = r
    graph_result.code 	 = c
    graph_result.headers = h
    graph_result.status  = s
    graph_result.data    = response:concat()
  else
    error 'Unsupported request method. Facebook supports whether GET, DELETE or POST requests.'
  end

  -- If the response contains a redirect (such as to an image), return the
  -- redirect as the data. i.e. https://graph.facebook.com/v2.3/19292868552/picture.
  if
    (301 == graph_result.code or 302 == graph_result.code or 307 == graph_result.code) and
    not empty(graph_result.headers.location)
  then
    output.data = {
      data = graph_result.data,
      redirect_code = graph_result.code,
      redirect_url = graph_result.headers.location,
    }
  else
    output = json.decode(graph_result.data)
  end

  return output
end

--[[ Return an Ophal User ID given a Facebook ID.
]]
function _M.facebook_get_user_id(fb_id)
  local rs = db_query('SELECT user_id FROM oauth2_facebook_users WHERE fb_id = ?', fb_id)
  local row = rs:fetch(true)
  return (row and row.user_id) and tonumber(row.user_id) or nil
end

function _M.facebook_login_user(account)
  module_invoke_all('user_login', account, output)
  _SESSION.user = account
end


--[[ Save a Ophal User ID to Facebook ID pairing.
]]
function _M.facebook_save_user(user_id, fb_id)
  if not empty(user_id) and not empty(fb_id) then
    -- Delete the existing Facebook ID if present for this Drupal user and
    -- make sure no other Ophal account is connected with this Facebook ID.
    db_query('DELETE FROM oauth2_facebook_users WHERE user_id = ? OR fb_id = ?', user_id, fb_id)

    db_query('INSERT INTO oauth2_facebook_users(user_id, fb_id, created) VALUES(?, ?, ?)', user_id, fb_id, time())
  end
end

function _M.facebook_callback()
  local output = {}
  local access_token, fb_data

  if _GET.error then
    output.error = t('User has denied to allow access.')
  elseif not empty(_GET.code) and config.facebook.app_id and config.facebook.app_secret then
    local res = _M.facebook_get_authcodes(_GET.code)
    if res and not empty(res.access_token) then
      _SESSION.oauth2.facebook = res

      local id = 'me' -- Versions prior to v2.4 and v2.5 are working with just this.
      if 'v2.4' == config.facebook.api_version or 'v2.5' == config.facebook.api_version then
	fb_data = _M.facebook_graph_query(id, res.access_token, {fields = 'email,name,first_name,last_name,age_range,link,gender,locale,timezone,updated_time,verified,birthday,location'})
      else
	fb_data = _M.facebook_graph_query(id, res.access_token)
      end

      -- Use fake email if user email not available.
      if empty(fb_data.email) then
	fb_data.email = fb_data.id .. '@facebook.com'
      end

      local user_id = _M.facebook_get_user_id(fb_data.id)

      if empty(user_id) then
	local account
	-- Lookup user from email address
	account = user_mod.load_by_field('mail', fb_data.email)

	if account then
	  user_id = account.id
	else
	  user_id = user_mod.create{name = fb_data.name,
	    mail = fb_data.email,
	    pass = '',
	    active = true,
	  }
	end
      end

      if not empty(user_id) then
	_M.facebook_login_user(user_mod.load(user_id))
      else
	error 'ERROR: Can not create requested user account.'
      end

      if user_mod.is_logged_in() then
	-- The user is already logged in to Drupal.
	-- So just associate the two accounts.
	_M.facebook_save_user(user_mod.current().id, fb_data.id)
      else
	error 'ERROR: Authentication failed!'
      end

      goto()
    end
  end

  return output
end

function theme.oauth2_google_connect(variables)
  local variables = variables or {}

  local base_url = 'https://accounts.google.com/o/oauth2'
  local params = {
    scope = 'https://www.googleapis.com/auth/analytics.readonly',
    state = _M.google_get_nonce(variables.resource),
    redirect_uri = ('%s://%s/oauth2/callback'):format(site.scheme or 'http', _SERVER 'SERVER_NAME'),
    response_type = 'code',
    client_id = config.google.client_id,
    access_type = 'offline',
    approval_prompt = 'force',
  }

  local connect_url = base_url .. '/auth?' .. _M.build_params(params)

  return l('Connect to Google API', connect_url, {external = true})
end

function theme.oauth2_facebook_connect_link(variables)
  local variables = variables or {}

  local base_url = 'https://www.facebook.com/v2.3/dialog/oauth'
  local params = {
    client_id = config.facebook.app_id,
    redirect_uri = url('oauth2/facebook/', {absolute = true}),
    scope = variables.scope and variables.scope or 'email,user_friends',
  }

  local connect_url = base_url .. '?' .. _M.build_params(params)

  local options = {
    external = true,
  }

  for k, v in pairs(variables.options or {}) do
    options[k] = v
  end

  return l(
    variables.label and variables.label or 'Connect to Facebook',
    connect_url, options
  )
end

return _M
