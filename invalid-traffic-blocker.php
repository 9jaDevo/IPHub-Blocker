<?php

/**
 * Plugin Name: Invalid Traffic Blocker
 * Plugin URI: https://github.com/9jaDevo/IPHub-Blocker
 * Description: Blocks unwanted traffic using the IPHub.info API to protect AdSense publishers from invalid traffic.
 * Version: 1.2
 * Author: Michael Akinwumi
 * Author URI: https://michaelakinwumi.com/
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: IPHub-Blocker
 * Requires at least: 4.5
 * Requires PHP: 7.2
 */

if (! defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

class Invalid_Traffic_Blocker_Plugin
{

    private $option_group = 'invalid_traffic_blocker_options';
    private $option_name  = 'invalid_traffic_blocker_options';

    public function __construct()
    {
        // Load settings on admin init.
        add_action('admin_menu', [$this, 'add_settings_page']);
        add_action('admin_init', [$this, 'register_settings']);

        // AJAX test for API connectivity.
        add_action('wp_ajax_itb_test_api', [$this, 'test_api_connectivity']);

        // Frontend check to block visitors.
        add_action('init', [$this, 'check_visitor_ip']);
    }

    /**
     * Add settings page under Settings menu.
     */
    public function add_settings_page()
    {
        add_options_page(
            'Invalid Traffic Blocker Settings',
            'Invalid Traffic Blocker',
            'manage_options',
            'invalid_traffic_blocker',
            [$this, 'render_settings_page']
        );
    }

    /**
     * Register plugin settings using the Settings API.
     */
    public function register_settings()
    {
        register_setting($this->option_group, $this->option_name, [__CLASS__, 'sanitize_settings']);

        add_settings_section(
            'itb_main_section',
            'Main Settings',
            null,
            'invalid_traffic_blocker'
        );

        // API Key field.
        add_settings_field(
            'api_key',
            'IPHub API Key',
            [$this, 'render_api_key_field'],
            'invalid_traffic_blocker',
            'itb_main_section'
        );

        // Enable/disable toggle.
        add_settings_field(
            'enabled',
            'Enable Invalid Traffic Blocker',
            [$this, 'render_enabled_field'],
            'invalid_traffic_blocker',
            'itb_main_section'
        );

        // Blocking mode checkboxes.
        add_settings_field(
            'blocking_modes',
            'Blocking Options (Select one)',
            [$this, 'render_blocking_modes_field'],
            'invalid_traffic_blocker',
            'itb_main_section'
        );

        // Custom Mode: Select specific block types.
        add_settings_field(
            'custom_block_options',
            'Custom Block Options',
            [$this, 'render_custom_block_options_field'],
            'invalid_traffic_blocker',
            'itb_main_section'
        );

        // Whitelisted IP addresses.
        add_settings_field(
            'whitelisted_ips',
            'Whitelist IP Addresses',
            [$this, 'render_whitelist_field'],
            'invalid_traffic_blocker',
            'itb_main_section'
        );
    }

    /**
     * Sanitize and validate settings input.
     */
    public static function sanitize_settings($input)
    {
        $new_input = array();

        $new_input['api_key'] = isset($input['api_key']) ? sanitize_text_field($input['api_key']) : '';
        $new_input['enabled'] = isset($input['enabled']) ? absint($input['enabled']) : 0;

        // Blocking modes.
        $new_input['safe_mode']   = isset($input['safe_mode']) ? 1 : 0;
        $new_input['strict_mode'] = isset($input['strict_mode']) ? 1 : 0;
        $new_input['custom_mode'] = isset($input['custom_mode']) ? 1 : 0;

        // If custom mode is active, store an array of allowed block types (1 and/or 2).
        if (! empty($new_input['custom_mode'])) {
            $custom = [];
            if (isset($input['custom_block_options']) && is_array($input['custom_block_options'])) {
                foreach ($input['custom_block_options'] as $block_option) {
                    $custom[] = absint($block_option);
                }
            }
            $new_input['custom_block_options'] = $custom;
        } else {
            $new_input['custom_block_options'] = [];
        }

        // Ensure only one blocking mode is active.
        $modes_active = (int)$new_input['safe_mode'] + (int)$new_input['strict_mode'] + (int)$new_input['custom_mode'];
        if ($modes_active > 1) {
            add_settings_error('invalid_traffic_blocker_options', 'mode_error', 'Please select only one blocking mode option.', 'error');
            // Default to safe mode if multiple selected.
            $new_input['safe_mode']   = 1;
            $new_input['strict_mode'] = 0;
            $new_input['custom_mode'] = 0;
            $new_input['custom_block_options'] = [];
        }

        // Sanitize the whitelisted IP addresses.
        if (isset($input['whitelisted_ips'])) {
            // Remove extra whitespace and ensure one IP per line.
            $lines = explode("\n", $input['whitelisted_ips']);
            $ips   = array();
            foreach ($lines as $line) {
                $ip = trim(sanitize_text_field($line));
                if (! empty($ip)) {
                    $ips[] = $ip;
                }
            }
            // Save as a newline-separated string.
            $new_input['whitelisted_ips'] = implode("\n", $ips);
        } else {
            $new_input['whitelisted_ips'] = '';
        }

        return $new_input;
    }

    /**
     * Render the API Key input field.
     */
    public function render_api_key_field()
    {
        $options = get_option($this->option_name);
?>
        <input type="text" name="<?php echo esc_attr($this->option_name); ?>[api_key]" value="<?php echo isset($options['api_key']) ? esc_attr($options['api_key']) : ''; ?>" size="40" />
    <?php
    }

    /**
     * Render the enable/disable toggle field.
     */
    public function render_enabled_field()
    {
        $options = get_option($this->option_name);
        $enabled = isset($options['enabled']) ? (int)$options['enabled'] : 0;
    ?>
        <input type="checkbox" name="<?php echo esc_attr($this->option_name); ?>[enabled]" value="1" <?php checked($enabled, 1); ?> />
    <?php
    }

    /**
     * Render the blocking mode options.
     */
    public function render_blocking_modes_field()
    {
        $options = get_option($this->option_name);
        $safe   = isset($options['safe_mode']) ? (int)$options['safe_mode'] : 0;
        $strict = isset($options['strict_mode']) ? (int)$options['strict_mode'] : 0;
        $custom = isset($options['custom_mode']) ? (int)$options['custom_mode'] : 0;
    ?>
        <label>
            <input type="checkbox" name="<?php echo esc_attr($this->option_name); ?>[safe_mode]" value="1" <?php checked($safe, 1); ?> /> Safe Mode (Block only non‑residential IPs: block==1)
        </label><br />
        <label>
            <input type="checkbox" name="<?php echo esc_attr($this->option_name); ?>[strict_mode]" value="1" <?php checked($strict, 1); ?> /> Strict Mode (Block both non‑residential and residential IPs: block==1 or block==2)
        </label><br />
        <label>
            <input type="checkbox" name="<?php echo esc_attr($this->option_name); ?>[custom_mode]" value="1" <?php checked($custom, 1); ?> /> Custom Mode (Select specific block types below)
        </label>
        <p><em>Please select only one mode.</em></p>
    <?php
    }

    /**
     * Render custom block options (only applicable if custom mode is enabled).
     */
    public function render_custom_block_options_field()
    {
        $options = get_option($this->option_name);
        $custom_options = isset($options['custom_block_options']) ? (array)$options['custom_block_options'] : [];
    ?>
        <label>
            <input type="checkbox" name="<?php echo esc_attr($this->option_name); ?>[custom_block_options][]" value="1" <?php checked(in_array(1, $custom_options)); ?> /> Block type 1 (Non‑residential)
        </label><br />
        <label>
            <input type="checkbox" name="<?php echo esc_attr($this->option_name); ?>[custom_block_options][]" value="2" <?php checked(in_array(2, $custom_options)); ?> /> Block type 2 (Residential suspicious)
        </label>
    <?php
    }

    /**
     * Render the whitelist IP addresses field.
     */
    public function render_whitelist_field()
    {
        $options = get_option($this->option_name);
        $whitelist = isset($options['whitelisted_ips']) ? $options['whitelisted_ips'] : '';
    ?>
        <textarea name="<?php echo esc_attr($this->option_name); ?>[whitelisted_ips]" rows="5" cols="50"><?php echo esc_textarea($whitelist); ?></textarea>
        <p class="description">Enter one IP address per line. These IPs will bypass the block checks.</p>
    <?php
    }

    /**
     * Render the plugin settings page.
     */
    public function render_settings_page()
    {
        $admin_ip = isset($_SERVER['REMOTE_ADDR']) ? wp_unslash($_SERVER['REMOTE_ADDR']) : '';
    ?>
        <div class="wrap">
            <h1>Invalid Traffic Blocker Settings</h1>
            <form method="post" action="options.php">
                <?php
                settings_fields($this->option_group);
                do_settings_sections('invalid_traffic_blocker');
                submit_button();
                ?>
            </form>
            <p>
                <a href="https://iphub.info/register" target="_blank" class="button button-secondary">Register for IPHub.info</a>
            </p>
            <p>
                <button id="itb-test-api" class="button">Test API Connectivity (Using Your IP)</button>
                <button id="itb-whitelist-my-ip" class="button">Whitelist My IP</button>
            </p>
            <div id="itb-test-result" style="margin-top:10px;"></div>
        </div>
        <script type="text/javascript">
            jQuery(document).ready(function($) {
                // Test API Connectivity.
                $('#itb-test-api').on('click', function(e) {
                    e.preventDefault();
                    var data = {
                        action: 'itb_test_api',
                        _ajax_nonce: '<?php echo esc_js(wp_create_nonce("itb_test_api_nonce")); ?>'
                    };
                    $.post(ajaxurl, data, function(response) {
                        $('#itb-test-result').html(response);
                    });
                });

                // Whitelist My IP button functionality.
                var adminIP = '<?php echo esc_js($admin_ip); ?>';
                $('#itb-whitelist-my-ip').on('click', function(e) {
                    e.preventDefault();
                    var $textarea = $('textarea[name="<?php echo esc_attr($this->option_name); ?>[whitelisted_ips]"]');
                    var currentValue = $textarea.val();
                    var ips = currentValue.split("\n").map(function(ip) {
                        return ip.trim();
                    }).filter(function(ip) {
                        return ip.length > 0;
                    });
                    if (ips.indexOf(adminIP) === -1) {
                        if (currentValue.length > 0) {
                            $textarea.val(currentValue + "\n" + adminIP);
                        } else {
                            $textarea.val(adminIP);
                        }
                        alert("Admin IP (" + adminIP + ") added to whitelist.");
                    } else {
                        alert("Admin IP (" + adminIP + ") is already in the whitelist.");
                    }
                });
            });
        </script>
<?php
    }

    /**
     * AJAX callback to test API connectivity.
     * Uses the admin's current IP for the test.
     */
    public function test_api_connectivity()
    {
        check_ajax_referer('itb_test_api_nonce');
        $options = get_option($this->option_name);
        if (empty($options['api_key'])) {
            echo '<div style="border: 1px solid red; padding:10px; background-color:#f2dede; color:#a94442;">Error: API key is not set.</div>';
            wp_die();
        }
        $api_key = $options['api_key'];
        $test_ip = isset($_SERVER['REMOTE_ADDR']) ? wp_unslash($_SERVER['REMOTE_ADDR']) : '0.0.0.0';

        $response = wp_remote_get("http://v2.api.iphub.info/ip/" . $test_ip, [
            'headers' => ['X-Key' => $api_key],
            'timeout' => 5,
        ]);

        if (is_wp_error($response)) {
            echo '<div style="border: 1px solid red; padding:10px; background-color:#f2dede; color:#a94442;">Error: API Connection Error: ' . esc_html($response->get_error_message()) . '</div>';
            wp_die();
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code !== 200) {
            echo '<div style="border: 1px solid red; padding:10px; background-color:#f2dede; color:#a94442;">Error: API Error: HTTP Code ' . esc_html($code) . '</div>';
            wp_die();
        }

        $body = wp_remote_retrieve_body($response);
        echo '<div style="border: 1px solid green; padding:10px; background-color:#dff0d8; color:#3c763d;">Success: API Response: ' . esc_html($body) . '</div>';
        wp_die();
    }

    /**
     * Check the visitor's IP against the IPHub API and block if necessary.
     */
    public function check_visitor_ip()
    {
        // Do not check in admin area.
        if (is_admin()) {
            return;
        }

        // Retrieve settings.
        $options = get_option($this->option_name);
        if (empty($options['enabled']) || empty($options['api_key'])) {
            return;
        }
        $api_key = $options['api_key'];

        // Get visitor IP address.
        $visitor_ip = isset($_SERVER['REMOTE_ADDR']) ? wp_unslash($_SERVER['REMOTE_ADDR']) : '';

        // Check if IP is whitelisted.
        if (! empty($options['whitelisted_ips'])) {
            $whitelist = array_filter(array_map('trim', explode("\n", $options['whitelisted_ips'])));
            if (in_array($visitor_ip, $whitelist)) {
                return; // Skip further checks if whitelisted.
            }
        }

        // Cache API results using transients to minimize API calls.
        $transient_key = 'itb_check_' . md5($visitor_ip);
        $ip_data = get_transient($transient_key);

        if (false === $ip_data) {
            $response = wp_remote_get("http://v2.api.iphub.info/ip/" . $visitor_ip, [
                'headers' => ['X-Key' => $api_key],
                'timeout' => 5,
            ]);

            if (is_wp_error($response)) {
                // If API connection fails, consider allowing access.
                return;
            }

            $code = wp_remote_retrieve_response_code($response);
            if ($code !== 200) {
                // On non-200 responses, do not block.
                return;
            }

            $body = wp_remote_retrieve_body($response);
            $ip_data = json_decode($body, true);

            // Cache for one hour.
            set_transient($transient_key, $ip_data, HOUR_IN_SECONDS);
        }

        // Determine whether to block the visitor based on selected mode.
        $block_ip = false;
        if (! empty($options['safe_mode'])) {
            // Safe Mode: block if block == 1.
            if (isset($ip_data['block']) && (int)$ip_data['block'] === 1) {
                $block_ip = true;
            }
        } elseif (! empty($options['strict_mode'])) {
            // Strict Mode: block if block == 1 or 2.
            if (isset($ip_data['block']) && in_array((int)$ip_data['block'], [1, 2])) {
                $block_ip = true;
            }
        } elseif (! empty($options['custom_mode'])) {
            // Custom Mode: block if IP's block value is in admin-selected options.
            $custom_options = isset($options['custom_block_options']) ? (array)$options['custom_block_options'] : [];
            if (isset($ip_data['block']) && in_array((int)$ip_data['block'], $custom_options)) {
                $block_ip = true;
            }
        }

        if ($block_ip) {
            // Display a persistent, non-dismissible warning message.
            wp_die(
                '<h1>Access Restricted</h1>
                <p>Your access has been restricted because your IP address has been flagged as suspicious (e.g., use of VPN or invalid traffic).</p>
                <p>Please disable your VPN or contact your network administrator if you believe this is an error.</p>',
                'Access Restricted',
                ['response' => 403]
            );
        }
    }
}

new Invalid_Traffic_Blocker_Plugin();
