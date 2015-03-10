local _M = {
  resources = nil,
}
ophal.modules.oauth2 = _M

local seawolf = require 'seawolf'.__build('contrib', 'text')
local config = settings.oauth2
local xtable, time = seawolf.contrib.seawolf_table, os.time
local explode, env, tonumber = seawolf.text.explode, env, tonumber
local empty, goto = seawolf.variable.empty, goto
local db_query

function _M.init()
  db_query = env.db_query
end

function _M.cron()
  db_query('DELETE FROM nonce WHERE ? > created + ?', time(), config.nonce_ttl or 2*60)
end

function _M.route()
  local items = {}

  items['oauth2/callback'] = {
    page_callback = 'callback',
  }

  return items
end

function _M.valid_nonce(nonce)
  local rs = db_query('SELECT COUNT(*) total FROM oauth2_nonce WHERE id = ? AND ? <= created + ?', nonce, time(), config.nonce_ttl or 2*60)
  local count = rs:fetch(true)
  if count then
    return tonumber(count.total) > 0
  end
end

function _M.create_authcodes(entity)
  local rs = db_query('INSERT INTO oauth2_token(id, resource, access_token, refresh_token, user_id, created, changed, ttl) VALUES(?, ?, ?, ?, ?, ?, ?, ?)', entity.id, entity.resource, entity.access_token, entity.refresh_token, entity.user_id, time(), time(), entity.ttl)
end

function _M.load_authcodes(id)
  local rs = db_query('SELECT * FROM oauth2_token WHERE id = ?', id)
  return rs:fetch(true)
end

function _M.update_authcodes(entity)
  local rs = db_query('UPDATE oauth2_token SET access_token = ?, changed = ?, ttl = ? WHERE id = ?', entity.access_token, time(), entity.ttl, entity.id)
end

function _M.get_resource(id)
  if empty(_M.resources) then
    _M.resources = module_invoke_all 'oauth2_resource'
  end

  if not empty(_M.resources) then
    return _M.resources[id]
  end
end

function _M.get_authcodes(code)
  local json = require 'dkjson'
  local https = require 'ssl.https'
  local ltn12 = require 'ltn12'
  local body = _M.build_params{
    code = code,
    client_id = config.client_id,
    client_secret = config.client_secret,
    redirect_uri = ('http://%s/oauth2/callback'):format(_SERVER 'SERVER_NAME'),
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

function _M.callback()
  local state = explode('|', _GET.state)
  local resource_id = state[1]
  local nonce = state[2]

  local resource = _M.get_resource(resource_id)

  if _M.valid_nonce(nonce) and not empty(resource) then
    local res = _M.get_authcodes(_GET.code)
    res.id = _GET.code
    res.resource = resource_id
    res.user_id = 1
    res.ttl = res.expires_in
    _M.create_authcodes(res)
  end

  goto(resource.path)

  return ''
end

function _M.build_params(params)
  local url = require 'socket.url'
  local output = xtable()
  for k, v in pairs(params) do
    output:append(k .. '=' .. url.escape(v))
  end
  return output:concat '&'
end

function _M.get_nonce(resource)
  local uuid = require 'uuid'
  local nonce = uuid.new()
  local rs, err = db_query('INSERT INTO oauth2_nonce(id, created) VALUES(?, ?)', nonce, time())
  return resource .. '|' .. nonce
end

function _M.refresh_authcodes(id)
  local token = _M.load_authcodes(id)
  if not empty(token) then
    local json = require 'dkjson'
    local https = require 'ssl.https'
    local ltn12 = require 'ltn12'
    local body = _M.build_params{
      refresh_token = token.refresh_token,
      client_id = config.client_id,
      client_secret = config.client_secret,
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

function _M.get_token(resource, user_id)
  local rs, err = db_query('SELECT id, access_token, refresh_token, changed, ttl FROM oauth2_token WHERE resource = ? AND user_id = ? ORDER BY changed DESC', resource, user_id)
  local token = rs:fetch(true)
  if not empty(token) then
    if token.changed + token.ttl > time() then
      return token.access_token
    else
      res = _M.refresh_authcodes(token.id)
      if res then
        res.id = token.id
        res.ttl = res.expires_in
        _M.update_authcodes(res)
        return res.access_token
      end
    end
  end
end

function theme.oauth2_connect(variables)
  local variables = variables or {}

  local base_url = 'https://accounts.google.com/o/oauth2'
  local params = {
    scope = 'https://www.googleapis.com/auth/analytics.readonly',
    state = _M.get_nonce(variables.resource),
    redirect_uri = ('http://%s/oauth2/callback'):format(_SERVER 'SERVER_NAME'),
    response_type = 'code',
    client_id = config.client_id,
    access_type = 'offline',
    approval_prompt = 'force',
  }

  local connect_url = base_url .. '/auth?' .. _M.build_params(params)

  return l('Connect to Google API', connect_url, {external = true})
end

return _M
