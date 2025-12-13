ce dossier est composé de 4 scripts et 4 vulns:


QUERIES FOFA:

Path traversal:
- adobe coldfusion: app="Adobe-ColdFusion"

- cdata api: app="Jetty" && (title="CData API Server" || title="CData Connect" || title="CData Arc" || title="CData Sync")


RCEs:
- cacti: app="Cacti-Monitoring"

- learnpress: body="/themes/kingster/learnpress"
