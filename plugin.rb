# name: Discourse Phabricator Connect
# about: Connect Your Phabricator Account, Install and Setup discourse-oauth2-basic with phabircator is required!
# version: 0.0.1
# author: Yana Agun Siswanto

require_dependency 'auth/oauth2_authenticator.rb'

enabled_site_setting :discourse_phabricator_connect_enabled

class ::OmniAuth::Strategies::DiscoursePhabricator < ::OmniAuth::Strategies::OAuth2
  option :name, "discourse_phabricator"
  info do
    {
      id: access_token['id']
    }
  end

  def callback_url
    full_host + script_name + callback_path
  end
end

class ::DiscoursePhabricatorAuthenticator < ::Auth::OAuth2Authenticator
  def register_middleware(omniauth)
    omniauth.provider :discourse_phabricator,
                      name: 'discourse_phabricator',
                      setup: lambda { |env|
                        opts = env['omniauth.strategy'].options
                        opts[:client_id] = SiteSetting.phabricator_client_id
                        opts[:client_secret] = SiteSetting.phabricator_client_secret
                        opts[:provider_ignores_state] = false
                        opts[:client_options] = {
                          authorize_url: phabricator_authorize_url,
                          token_url: phabricator_token_url
                        }
                        opts[:authorize_options] = { scope: ['always'] }
                        opts[:token_params] = { headers: { 'Authorization' => basic_auth_header } }
                      }
  end
  
  def phabricator_authorize_url
    SiteSetting.phabricator_url + '/oauthserver/auth/'
  end

  def phabricator_token_url
    SiteSetting.phabricator_url + '/oauthserver/token/'
  end

  def basic_auth_header
    "Basic " + Base64.strict_encode64("#{SiteSetting.phabricator_client_id}:#{SiteSetting.phabricator_client_secret}")
  end

  def log(info)
    Rails.logger.warn("OAuth2 Debugging: #{info}")
  end

  def fetch_user_details(token, id)
    user_json_url = SiteSetting.phabricator_url + '/api/user.whoami?access_token=' + token

    user_json = JSON.parse(open(user_json_url, 'Authorization' => "Bearer #{token}").read)

    log("user_json: #{user_json}")

    result = {}
    if user_json.present?
      result[:user_id]           = user_json['result']['phid']
      result[:username]          = user_json['result']['userName']
      result[:name]              = user_json['result']['realName']
      result[:email]             = user_json['result']['primaryEmail']
      result[:phabricator_url]   = user_json['result']['uri']
      result[:phabricator_roles] = user_json['result']['roles']
      result[:phabricator_token] = token
    end
    result
  end

  def after_authenticate(auth)

    result = Auth::Result.new
    token = auth['credentials']['token']
    user_details = fetch_user_details(token, auth['info'][:id])

    result.name        = user_details[:name]
    result.username    = user_details[:username]
    result.email       = user_details[:email]
    result.email_valid = result.email.present? && SiteSetting.phabricator_email_verified?

    current_info = ::PluginStore.get("discourse_phabricator", "discourse_phabricator_user_#{user_details[:user_id]}")
    
    if current_info
      result.user = User.where(id: current_info[:user_id]).first
    elsif result.email.present?
      result.user = User.find_by_email(result.email)
      if result.user && user_details[:user_id]
        ::PluginStore.set(
          "discourse_phabricator",
          "discourse_phabricator_user_#{user_details[:user_id]}",
          user_id: result.user.id,
          authentification_token: token)
      end
    end
    if result.user
      result.user.custom_fields['discourse_phabricator_connect'] ||= {}
      user_details.each do |k,v|
        result.user.custom_fields['discourse_phabricator_connect'][k] = v
      end
      result.user.save_custom_fields
    end
    result.extra_data = {
      discourse_phabricator_user_id: user_details[:user_id],
      authentification_token: token
    }
    result  
  end

  def after_create_account(user, auth)
    user_details = fetch_user_details(
      auth[:extra_data][:authentification_token],
      auth[:extra_data][:discourse_phabricator_user_id]
    )
    user.custom_fields['discourse_phabricator_connect'] ||= {}
    user_details.each do |k,v|
      user.custom_fields['discourse_phabricator_connect'][k] = v
    end
    user.save_custom_fields
    
    user_details['user_id'] = user.id
    ::PluginStore.set(
      "discourse_phabricator",
      "discourse_phabricator_user_#{auth[:extra_data][:discourse_phabricator_user_id]}",
      user_details
    )
  end
end

auth_provider title_setting: "phabricator_button_login_title",
              enabled_setting: "discourse_phabricator_connect_enabled",
              authenticator: DiscoursePhabricatorAuthenticator.new('discourse_phabricator'),
              message: "OAuth2"

register_css <<CSS

  button.btn-social.discourse_phabricator {
    background-color: #6d6d6d;
  }

CSS

after_initialize do
  User.register_custom_field_type('discourse_phabricator_connect', :json)
  add_to_serializer(:current_user, :phabricator_url) do
    scope.user.custom_fields['discourse_phabricator_connect']['phabricator_url'] if scope.user.custom_fields['discourse_phabricator_connect'].present?
  end
  add_to_serializer(:user, :phabricator_url) do
    user.custom_fields['discourse_phabricator_connect']['phabricator_url'] if user.custom_fields['discourse_phabricator_connect'].present?
  end
end
