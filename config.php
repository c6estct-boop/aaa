<?php
// ---------------------------------------------------------------------------
// Vexis license api configuration
// ---------------------------------------------------------------------------
// local test:   php -S 127.0.0.1:8080 -t api  (veya api/start.bat)
// admin panel:  http://127.0.0.1:8080/admin.php
// api endpoint: http://127.0.0.1:8080/api.php
// ---------------------------------------------------------------------------

return [
    // sqlite works on nearly every shared host, no database setup needed.
    // switch to "mysql" and fill the block below if you prefer it.
    'db_driver' => 'sqlite',
    'sqlite_path' => __DIR__ . '/data/licenses.sqlite',

    'mysql' => [
        'host' => '127.0.0.1',
        'port' => 3306,
        'name' => 'vexis',
        'user' => 'root',
        'pass' => '',
    ],

    // CHANGE THIS BEFORE PUTTING THE PANEL ONLINE
    'admin_password' => 'vexisinternalpanelxd',

    // Shared client secret (compiled in loader). Change it together with
    // src/loader/license.cpp (k_api_secret) and rebuild Vexis.exe.
    'api_secret' => 'd31473bbb21943cd161145073eb5967ff54e05be7f33cde3',

    // Returned for banned / invalid / unsigned requests
    'ban_message' => 'invalid api request BANNED !',

    // Auto-ban IPs that send empty / unsigned / invalid requests.
    // Set to false if you ever lock yourself out while testing.
    'ban_enabled' => true,

    'timezone' => 'Europe/Istanbul',
    'api_version' => '1.0.0',
];
