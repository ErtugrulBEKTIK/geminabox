#
# This is a simple rackup file for geminabox. It allows simple role-based authorization.
#
# roles:
# - developer
# - upload
# - delete
# - admin (can do anything)
#
# For example, a developer who can access the service and upload new gems would have the following roles: `%w(developer upload)
#
$:.unshift(File.expand_path(File.join(File.dirname(__FILE__), "lib")))
require "rubygems"
require "geminabox"

USERS = {
  'admin' => { password: ENV["ADMIN_PASSWORD"], roles: %w(admin) },
  'developer' => { password: ENV["DEVELOPER_PASSWORD"], roles: %w(developer) }
}

use Rack::Session::Pool, expire_after: 1000 # sec
use Rack::Protection

Geminabox::Server.helpers do
  def protect!(role='developer')
    if env['REQUEST_PATH'] != '/api/v1/gems' && !has_role?(role)
      response['WWW-Authenticate'] = %(Basic realm="Gem In a Box")
      halt 401, "Not Authorized.\n"
    end
  end

  def auth
    @auth ||= Rack::Auth::Basic::Request.new(request.env)
  end

  def username
    auth ? auth.credentials.first : nil
  end

  def password
    auth ? auth.credentials.last : nil
  end

  def user_roles
    USERS[username][:roles]
  end

  def authenticated?
    return false unless auth.provided? && auth.basic? && auth.credentials
    api_key = USERS[username]
    !api_key.nil? && password == api_key[:password]
  end

  def current_user_roles
    authenticated? ? user_roles : []
  end

  def has_role?(role)
    current_user_roles.include?('admin') || current_user_roles.include?(role)
  end
end

Geminabox::Server.before '/upload' do
  protect!('upload')
end

Geminabox::Server.before do
  if request.delete?
    protect!('delete')
  else
    protect!('developer')
  end
end

Geminabox::Server.before '/api/v1/gems' do
  unless env['HTTP_AUTHORIZATION'] == ENV["API_KEY"]
    halt 401, "Access Denied. Api_key invalid or missing.\n"
  end
end

Geminabox::Server.post '/api/v1/api_key' do
  protect!('upload')

  status 200
  body ENV["API_KEY"]
end

run Geminabox::Server

