# Informe de enumeración de red 172.17.0.0/24

## 1. Resumen ejecutivo

Se identificaron 9 equipos activos en la red autorizada, ejecutando un total de 22 servicios TCP. Los riesgos más graves corresponden a Apache ActiveMQ 5.15.15 (172.17.0.5) con vulnerabilidad de ransomware en KEV, Samba smbd 4 (172.17.0.8) con dos CVEs en KEV asociados a ransomware, y Apache httpd/Tomcat en versiones con vulnerabilidades de alta severidad en catálogo KEV. Se recomienda revisar primero los servicios en KEV con mayor EPSS (ActiveMQ, Apache httpd 2.4.58/59, Samba y Tomcat 9.0.30).

## 2. Equipos y servicios

| Equipo | Puerto | Servicio y versión | Evidencia |
|---|---|---|---|
| 172.17.0.1 | 22/tcp | OpenSSH 10.6p2 Debian 1 | E10 |
| 172.17.0.3 | 21/tcp | vsftpd 2.3.4 | E02 |
| 172.17.0.3 | 80/tcp | Apache httpd 2.4.58 ((Ubuntu)) | E02 |
| 172.17.0.4 | 22/tcp | OpenSSH 7.9p1 Debian 10+deb10u4 | E03 |
| 172.17.0.4 | 8009/tcp | Apache Jserv (Protocol v1.3) | E03 |
| 172.17.0.4 | 8080/tcp | Apache Tomcat 9.0.30 | E03 |
| 172.17.0.5 | 80/tcp | Apache httpd 2.4.59 ((Debian)) | E04 |
| 172.17.0.5 | 443/tcp | Apache httpd 2.4.59 ((Debian)) | E04 |
| 172.17.0.5 | 1883/tcp | mqtt | E04 |
| 172.17.0.5 | 5672/tcp | amqp | E04 |
| 172.17.0.5 | 8161/tcp | Jetty 9.4.39.v20210325 | E04 |
| 172.17.0.5 | 38443/tcp | tcpwrapped | E04 |
| 172.17.0.5 | 61613/tcp | Apache ActiveMQ | E04 |
| 172.17.0.5 | 61614/tcp | Jetty 9.4.39.v20210325 | E04 |
| 172.17.0.5 | 61616/tcp | ActiveMQ OpenWire transport 5.15.15 | E04 |
| 172.17.0.6 | 22/tcp | OpenSSH 9.2p1 Debian 2+deb12u2 | E05 |
| 172.17.0.6 | 8080/tcp | Jetty 10.0.18 | E05 |
| 172.17.0.7 | 22/tcp | OpenSSH 7.7 | E06 |
| 172.17.0.8 | 22/tcp | OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 | E07 |
| 172.17.0.8 | 80/tcp | Apache httpd 2.4.58 ((Ubuntu)) | E07 |
| 172.17.0.8 | 139/tcp | Samba smbd 4 | E07 |
| 172.17.0.8 | 445/tcp | Samba smbd 4 | E07 |
| 172.17.0.9 | 22/tcp | OpenSSH 9.2p1 Debian 2+deb12u10 | E08 |
| 172.17.0.9 | 80/tcp | Apache httpd 2.4.68 ((Debian)) | E08 |
| 172.17.0.10 | 80/tcp | SimpleHTTPServer 0.6 (Python 3.11.2) | E09 |

## 3. Vulnerabilidades potenciales priorizadas

*Consulta de EPSS y KEV: 2026-11-25. Los valores cambian a diario.*

| # | Hallazgo | Equipo y servicio | CVSS (versión) | EPSS | KEV | CWE | Nivel de evidencia | Evidencia |
|---|---|---|---|---|---|---|---|---|
| 1 | CVE-2023-46604 | 172.17.0.5 · 61616/tcp ActiveMQ OpenWire transport 5.15.15 | 9.8 (3.1) | 1.000 | desde 2023-11-02 · ransomware | CWE-502 | potencial (solo versión) | E18 |
| 2 | CVE-2024-38475 | 172.17.0.3 · 80/tcp Apache httpd 2.4.58 | 9.1 (3.1) | 1.000 | desde 2025-05-01 | CWE-116 | potencial (solo versión) | E12 |
| 3 | CVE-2023-44487 | 172.17.0.4 · 8080/tcp Apache Tomcat 9.0.30 | 7.5 (3.1) | 1.000 | desde 2023-10-10 | CWE-400 | potencial (solo versión) | E14 |
| 4 | CVE-2025-24813 | 172.17.0.4 · 8080/tcp Apache Tomcat 9.0.30 | 9.8 (3.1) | 0.999 | desde 2025-04-01 | CWE-44, CWE-502, CWE-706 | potencial (solo versión) | E14 |
| 5 | CVE-2017-7494 | 172.17.0.8 · 139/tcp Samba smbd 4 | 9.8 (3.1) | 0.994 | desde 2023-03-30 · ransomware | CWE-94 | potencial (solo versión) | E24 |
| 6 | CVE-2020-1472 | 172.17.0.8 · 139/tcp Samba smbd 4 | 5.5 (3.1) | 0.994 | desde 2021-11-03 · ransomware | sin dato | potencial (solo versión) | E24 |
| 7 | CVE-2020-1938 | 172.17.0.4 · 8080/tcp Apache Tomcat 9.0.30 | 9.8 (3.1) | 0.993 | desde 2022-03-03 | sin dato | potencial (solo versión) | E14 |
| 8 | CVE-2026-34197 | 172.17.0.5 · 61616/tcp ActiveMQ OpenWire transport 5.15.15 | 8.8 (3.1) | 0.983 | desde 2026-04-16 | CWE-20, CWE-78, CWE-94 | potencial (solo versión) | E18 |
| 9 | CVE-2026-123158 | 172.17.0.4 · 22/tcp OpenSSH 7.9p1 | 8.1 (3.1) | 0.955 | desde 2026-11-09 | CWE-394 | potencial (solo versión) | E13 |
| 10 | CVE-2024-6387 | 172.17.0.6 · 22/tcp OpenSSH 9.2p1 | 8.1 (3.1) | 0.995 | no | CWE-362, CWE-364 | potencial (solo versión) | E19 |

**Criterio de ordenación:**
1. CVE-2023-46604: en KEV desde 2023-11-02, ransomware: sí, EPSS 1.000, CVSS 9.8 — máxima prioridad por ser el único con confirmación de ransomware y EPSS/CVSS máximos.
2. CVE-2024-38475: en KEV desde 2025-05-01, EPSS 1.000, CVSS 9.1 — EPSS máximo, CVSS alto.
3. CVE-2023-44487: en KEV desde 2023-10-10, EPSS 1.000, CVSS 7.5 — EPSS máximo, CVSS menor que los anteriores.
4. CVE-2025-24813: en KEV desde 2025-04-01, EPSS 0.999, CVSS 9.8 — segundo EPSS más alto, CVSS máximo.
5. CVE-2017-7494: en KEV desde 2023-03-30, ransomware: sí, EPSS 0.994, CVSS 9.8 — KEV + ransomware + CVSS 9.8.
6. CVE-2020-1472: en KEV desde 2021-11-03, ransomware: sí, EPSS 0.994, CVSS 5.5 — mismo EPSS que el anterior pero CVSS menor.
7. CVE-2020-1938: en KEV desde 2022-03-03, EPSS 0.993, CVSS 9.8 — EPSS ligeramente menor, CVSS máximo.
8. CVE-2026-34197: en KEV desde 2026-04-16, EPSS 0.983, CVSS 8.8 — siguiente EPSS en KEV.
9. CVE-2026-123158: en KEV desde 2026-11-09, EPSS 0.955, CVSS 8.1 — último en la lista KEV.
10. CVE-2024-6387: no en KEV, EPSS 0.995, CVSS 8.1 — mejor EPSS de los no-KEV.

## 4. A verificar

- **Versiones con backport posible (Debian/Ubuntu):** Apache httpd 2.4.58 en 172.17.0.3 y 172.17.0.8 indican `(Ubuntu)`; Apache httpd 2.4.59 en 172.17.0.5 indica `(Debian)`; Apache httpd 2.4.68 en 172.17.0.9 indica `(Debian)`. OpenSSH con sufijos Debian/Ubuntu en 172.17.0.4 (`Debian 10+deb10u4`), 172.17.0.6 (`Debian 2+deb12u2`), 172.17.0.9 (`Debian 2+deb12u10`), 172.17.0.8 (`Ubuntu 3ubuntu13.5`), 172.17.0.1 (`Debian 1`). Estos sistemas podrían tener parches retroportados no reflejados en la versión del banner.
- **Búsquedas por palabras clave (mayor ruido):** vsftpd 2.3.4 (E11), Jetty 9.4.39.v20210325 (E17), Jetty 10.0.18 (E20), SimpleHTTPServer 0.6 (E28), OpenSSH 10.6p2 (E29). Las búsquedas por palabras clave pueden traer resultados menos precisos.
- **Servicios sin versión detectada:** mqtt en 172.17.0.5:1883, amqp en 172.17.0.5:5672, tcpwrapped en 172.17.0.5:38443, Apache ActiveMQ en 172.17.0.5:61613, Apache Jserv en 172.17.0.4:8009. Sin versión, no se pudo buscar CVE.
- **Servicios sin CVE candidatos:** Jetty 9.4.39.v20210325 (E17, E04), Jetty 10.0.18 (E20), SimpleHTTPServer 0.6 (E28). Esto no demuestra que estén libres de vulnerabilidades.
