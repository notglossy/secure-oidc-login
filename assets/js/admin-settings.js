/**
 * Admin settings page JavaScript for OIDC discovery functionality.
 *
 * Handles the "Discover" button click to auto-populate OIDC endpoints
 * from the identity provider's .well-known/openid-configuration document.
 *
 * @package Secure_OIDC_Login
 */

(function($) {
	'use strict';

	$(document).ready(function() {
		// Handle click on "Discover" button
		$('#oidc-discover-btn').on('click', function(e) {
			e.preventDefault();
			var discoveryUrl = $('#discovery_url').val();

			// Validate that user entered a discovery URL
			if (!discoveryUrl) {
				alert(oidcAdminSettings.i18n.enterDiscoveryUrl);
				return;
			}

			// Update button state to show discovery in progress
			var $button = $(this);
			$button.prop('disabled', true).text(oidcAdminSettings.i18n.discovering);

			// Fetch the OIDC discovery document from the IdP via AJAX
			// This calls ajax_discover() which fetches .well-known/openid-configuration
			$.ajax({
				url: oidcAdminSettings.ajaxUrl,
				type: 'POST',
				data: {
					action: 'oidc_discover',
					discovery_url: discoveryUrl,
					nonce: oidcAdminSettings.nonce
				},
				success: function(response) {
					if (response.success) {
						// Auto-populate endpoint fields from discovery document
						// Each endpoint is optional in the OIDC spec, so we check before populating
						var config = response.data;

						if (config.authorization_endpoint) {
							$('input[name="secure_oidc_login_settings[authorization_endpoint]"]').val(config.authorization_endpoint);
						}
						if (config.token_endpoint) {
							$('input[name="secure_oidc_login_settings[token_endpoint]"]').val(config.token_endpoint);
						}
						if (config.userinfo_endpoint) {
							$('input[name="secure_oidc_login_settings[userinfo_endpoint]"]').val(config.userinfo_endpoint);
						}
						if (config.end_session_endpoint) {
							$('input[name="secure_oidc_login_settings[end_session_endpoint]"]').val(config.end_session_endpoint);
						}
						if (config.jwks_uri) {
							$('input[name="secure_oidc_login_settings[jwks_uri]"]').val(config.jwks_uri);
						}
						if (config.issuer) {
							$('input[name="secure_oidc_login_settings[issuer]"]').val(config.issuer);
						}

						alert(oidcAdminSettings.i18n.discoverySuccess);
					} else {
						// Discovery failed - show error message from server
						alert(response.data || oidcAdminSettings.i18n.discoveryFailed);
					}
				},
				error: function() {
					// Network error or server error
					alert(oidcAdminSettings.i18n.discoveryRequestFailed);
				},
				complete: function() {
					// Re-enable button whether success or failure
					$button.prop('disabled', false).text(oidcAdminSettings.i18n.discover);
				}
			});
		});
	});

})(jQuery);
