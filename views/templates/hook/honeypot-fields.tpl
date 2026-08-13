{**
 * Honeypot-Felder fuer das Kontaktformular.
 * Fuer Menschen per CSS unsichtbar (display:none), fuer einfache
 * Spam-Bots aber ganz normal vorhandene Text-Eingabefelder. Die
 * Feldnamen sind im Backend konfigurierbar (siehe honeypod_antispam.php).
 * Zusaetzlich ein verstecktes, signiertes Zeit-Token, mit dem zu schnell
 * abgeschickte (also automatisierte) Anfragen erkannt werden.
 *}
<style>
  .hpa-hp {
    display: none !important;
  }
</style>

<div class="hpa-hp" aria-hidden="true">
  {foreach $hpa_fields as $hpa_field}
    <label for="hpa_{$hpa_field|escape:'html':'UTF-8'}">{$hpa_field|escape:'html':'UTF-8'}</label>
    <input type="text" id="hpa_{$hpa_field|escape:'html':'UTF-8'}" name="{$hpa_field|escape:'html':'UTF-8'}" value="" tabindex="-1" autocomplete="off">
  {/foreach}
</div>

<input type="hidden" name="{$hpa_timing_field|escape:'html':'UTF-8'}" value="{$hpa_timing_token|escape:'html':'UTF-8'}">
