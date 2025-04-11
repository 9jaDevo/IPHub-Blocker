jQuery(document).ready(function ($) {
    // Handle API connectivity test.
    $('#invatrbl-test-api').on('click', function (e) {
        e.preventDefault();
        var data = {
            action: 'invatrbl_test_api',
            _ajax_nonce: invatrblVars.nonce
        };
        $.post(invatrblVars.ajaxUrl, data, function (response) {
            $('#invatrbl-test-result').html(response);
        });
    });

    // Handle "Whitelist My IP" button.
    var adminIP = invatrblVars.adminIP;
    $('#invatrbl-whitelist-my-ip').on('click', function (e) {
        e.preventDefault();
        var $textarea = $('textarea[name="' + invatrblVars.optionName + '[whitelisted_ips]"]');
        var currentValue = $textarea.val();
        var ips = currentValue.split("\n").map(function (ip) {
            return ip.trim();
        }).filter(function (ip) {
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
