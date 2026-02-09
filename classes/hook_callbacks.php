<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

namespace auth_oidc;

use core\hook\after_config;

/**
 * Class hook_callbacks
 *
 * @package    auth_oidc
 * @author     Scott Verbeek <scottverbeek@catalyst-au.net>
 * @copyright  2025 Catalyst IT
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class hook_callbacks {
    /**
     * Check if we have the oidc=1 param set. If so, disable guest access and force the user to log in with oidc.
     * @param after_config $hook
     */
    public static function after_config(after_config $hook) {
        global $CFG, $PAGE, $FULLME, $SESSION;
        try {
            $oidc = optional_param('oidc', 0, PARAM_BOOL);
            if ($oidc == 1) {
                if (isguestuser()) {
                    // We want to force users to log in with a real account, so log guest users out.
                    require_logout();
                }
                // We have the oidc=1 param set. Disable guest access (in memory -
                // not saved in database) to force the login with oidc for this request.
                unset($CFG->autologinguests);

                // Set the return URL.
                if ($url = qualified_me()) {
                    $wantsurl = new \moodle_url($url);
                    $wantsurl->remove_params('oidc');
                    $SESSION->wantsurl = $wantsurl->out(false);
                }

                // Force the redirect to login.
                redirect(new \moodle_url('/auth/oidc/'));
                die;
            }
        } catch (\Exception $exception) {
            // @codingStandardsIgnoreStart
            // We never want this to throw a real exception. But log the error.
            error_log('auth_oidc_after_config error! ' . $exception->getTraceAsString());
            // @codingStandardsIgnoreEnd
        }
    }
}
