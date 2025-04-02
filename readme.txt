=== Invalid Traffic Blocker ===
Contributors: michaelakinwumi
Tags: invalid traffic, ip, iphub, blocker, ad protection, VPN, security
Requires at least: 4.5
Tested up to: 6.7.2
Stable tag: 1.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Requires PHP: 7.2
Text Domain: invalid-traffic-blocker

== Description ==
Invalid Traffic Blocker is a powerful plugin that protects your website from unwanted and suspicious traffic. Using the IPHub.info API, the plugin blocks traffic from bots, VPNs, and other sources of invalid visits. It is especially useful for AdSense publishers who need to ensure that only legitimate traffic is served on their sites. With multiple blocking modes and the option to whitelist trusted IP addresses, you have full control over which visitors are allowed access.

== Installation ==
1. Upload the plugin files to the `/wp-content/plugins/invalid-traffic-blocker` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Navigate to `Settings > Invalid Traffic Blocker` in your WordPress admin dashboard.
4. Enter your IPHub API key, choose your desired blocking mode (Safe, Strict, or Custom), and add any trusted IP addresses to the whitelist.
5. Save your settings and test the API connectivity using the built-in test button.

== Frequently Asked Questions ==
= What is Invalid Traffic Blocker? =
Invalid Traffic Blocker is a WordPress plugin that uses the IPHub.info API to detect and block unwanted traffic, including bots, VPNs, and suspicious IP addresses. It helps ensure that only valid traffic reaches your website.

= How do I configure the plugin? =
After activating the plugin, go to `Settings > Invalid Traffic Blocker`. Here you can enter your API key, select a blocking mode, and manage your IP whitelist.

= What if my API key is missing or invalid? =
If the API key is missing or incorrect, the plugin will not perform any blocking. Make sure to obtain a valid API key from [IPHub.info](https://iphub.info/register).

= Can I update the whitelist later? =
Yes, you can update the list of whitelisted IP addresses at any time from the settings page.

== Changelog ==
= 1.1 =
* Added whitelist functionality for trusted IP addresses.
* Improved error handling and caching for API requests.
* Enhanced the admin interface for a better user experience.

= 1.0 =
* Initial release with core functionality:
  - Integration with IPHub.info API.
  - Multiple blocking modes: Safe, Strict, and Custom.
  - Persistent warning message for blocked users.
  - Basic security measures and caching implementation.

== Upgrade Notice ==
= 1.1 =
This update introduces whitelist functionality along with various improvements. We recommend updating to ensure optimal performance and security.

== Screenshots ==
1. Admin settings page with API key and blocking mode options.
2. Whitelist IP addresses field.
3. Warning message displayed to blocked users.
