<?php
if (! defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Delete the options set by the plugin
delete_option('invalid_traffic_blocker_options');
