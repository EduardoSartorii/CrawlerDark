/*
 * Exemplo mínimo de regra YARA. Só é utilizada se `yara-python` estiver instalado.
 * Detecção fictícia para demonstração do carregamento.
 */
rule ExampleLeakMarker
{
    meta:
        author = "threat-hunting"
        description = "Marcadores típicos de dumps de credenciais"
        severity = "HIGH"
    strings:
        $s1 = "combolist" nocase
        $s2 = "user:pass" nocase
        $s3 = ":password:" nocase
    condition:
        any of them
}
