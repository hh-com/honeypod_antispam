<?php
/**
 * Upgrade auf 1.1.0.
 *
 * @author    Harald Huber
 * @copyright Harald Huber
 * @link      https://www.harald-huber.com
 * @license   Proprietary - all rights reserved. Not for redistribution.
 *
 * Legt die Tabelle fuer Rate-Limiting/Statistik an und ergaenzt die
 * neuen Konfigurationswerte (Honeypot-Feldnamen, Zeitschwelle,
 * Inhalts-Heuristik, Rate-Limit) mit ihren Standardwerten, ohne bereits
 * vorhandene Werte (z.B. HPA_BLOCKED_COUNT) zu ueberschreiben.
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * @param Honeypod_Antispam $module
 *
 * @return bool
 */
function upgrade_module_1_1_0(Honeypod_Antispam $module)
{
    return $module->createAttemptTable()
        && $module->installDefaultConfigurationIfMissing();
}
