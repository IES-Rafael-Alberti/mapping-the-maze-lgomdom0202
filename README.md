# Mapping the Maze - Gadir Logística, S.L.

**Grupo:** Luis Miguel Gomila Domínguez, Gonzalo García Vega, Natalia Alejo Pérez y Pablo Ostenero Reyes
**Alcance autorizado:** `172.17.0.0/24` (ver [scope.txt](scope.txt))
**Tipo de trabajo:** identificación activa no intrusiva, sin explotación

Cada integrante hizo las Partes 0 a 4 sobre su propia copia de la red del cliente y tiene su
propio cuaderno, sus evidencias y sus capturas. **Los cuadernos son individuales; los tres
entregables ([inventario.md](inventario.md), [registro-vulns.md](registro-vulns.md) e
[informe-cliente.md](informe-cliente.md)) son de los cuatro.** Los hicimos poniendo en común y
contrastando lo que obtuvo cada uno: lo que encontramos todos figura como trabajo del grupo, y lo
que sacó solo una persona lleva su nombre.

Cada dato se puede rastrear hasta un comando del cuaderno de quien lo obtuvo, con su salida en
`evidencias/EVIDENCIAS_<NOMBRE>/` y su captura en `imagenes/CAPTURAS_<NOMBRE>/`. Como cada uno
escaneó una copia distinta de la red, las tablas de los entregables citan una sola copia como
referencia (la de Luis Miguel, `EVIDENCIAS_LUISMI`); los otros tres obtuvimos los mismos resultados
en las nuestras, y las diferencias están señaladas.

## Documentos

| Parte | Documento |
|---|---|
| 1. Descubrir y mapear | [inventario.md](inventario.md) |
| 2. Enumerar sin autenticar | [inventario.md](inventario.md) (apartado Parte 2) |
| 3. De la versión al CVE | [registro-vulns.md](registro-vulns.md) |
| 4. Priorizar e informar | [registro-vulns.md](registro-vulns.md), [informe-cliente.md](informe-cliente.md) |

## Trabajo en común del grupo

Los cuatro llegamos por separado, cada uno en su red, a los mismos resultados principales:
- **Inventario:** los mismos 8 equipos vivos (172.17.0.3 a 172.17.0.10), los mismos 24 puertos TCP
  con sus versiones y los mismos 2 servicios UDP (137/udp en la .8 y 623/udp en la .10). La única
  diferencia es el número del puerto sin identificar de la .5, que cambia en cada copia de la red.
- **Hoja del cliente:** la misma conclusión (7 entradas sobran, 2 tienen datos erróneos, faltan 6
  equipos y 1 queda fuera del alcance).
- **Hallazgos principales:** vsftpd 2.3.4 en la .3, ActiveMQ 5.15.15 en la .5, Tomcat 9.0.30 en la
  .4, Jenkins 2.441 en la .6 e IPMI 2.0 en la .10.
- **Aviso de la noticia («sshole»):** los cuatro lo revisamos; la .7 es el equipo que no se puede
  descartar.

Al juntar el trabajo, cada aportación individual se añadió a los entregables con el nombre de quien
la hizo. Las tablas «Contraste con el trabajo del grupo» de [inventario.md](inventario.md) y
[registro-vulns.md](registro-vulns.md) recogen quién encontró cada cosa, y también las diferencias
de criterio (por ejemplo, el uso de sesiones nulas de SMB o de `-O`).

## Aportación de cada integrante

### Luis Miguel Gomila Domínguez → [cuaderno](cuadernos/luis-miguel-gomila-dominguez.md)
- Sus evidencias son la copia de referencia de las tablas de los entregables.
- Descubrimiento con ICMP, TCP, UDP y ARP; `-p-` de todos los equipos; UDP ampliado a 1000 puertos
  (100 en la .7, a `--max-rate 10`).
- Elección de la .7 como equipo delicado y escaneo a velocidad limitada, vigilado con `ping`.
- Aportaciones que solo están en su trabajo: la versión de ActiveMQ leída del `WireFormatInfo`
  (61616), que AMQP habla la versión 1.0, la verificación del banner de Apache 2.4.68, y los
  hallazgos V-04 a V-07, V-09 a V-11 y V-13 con sus trackers de Debian y Ubuntu.
- Método de priorización por tramos y respuesta al aviso con NVD, cve.org, EPSS, KEV y trackers.
- Evidencias en [evidencias/EVIDENCIAS_LUISMI/](evidencias/EVIDENCIAS_LUISMI/) y capturas en
  [imagenes/CAPTURAS_LUISMI/](imagenes/CAPTURAS_LUISMI/).

### Gonzalo García Vega → [cuaderno](cuadernos/gonzalo-garciavega-1.md)
- Inventario completo (`-p-`, versiones y UDP de 1000 puertos en los ocho equipos) y detección de
  sistema operativo con `-O`: Linux en los ocho equipos, también en la .7, dato que se usa en V-13.
- Enumeración de cada servicio, con dos aportaciones propias que están en los entregables:
  - STOMP de ActiveMQ acepta conexiones sin credenciales (C-11).
  - Rutas de administración que anuncia Tomcat (C-12).
- Cuentas de Samba con `rpcclient` y listado de recursos con `smbclient -N -L` (C-10, junto con Natalia).
- EPSS y KEV de CVE-2024-38475, que está en KEV y faltaba en el registro (V-14), y de CVE-2026-119618 (V-15).
- Ficha de CVE-2013-4786 (IPMI) a partir de la referencia de la web de la .10.
- Evidencias en [evidencias/EVIDENCIAS_GONZALO/](evidencias/EVIDENCIAS_GONZALO/) y capturas en
  [imagenes/CAPTURAS_GONZALO/](imagenes/CAPTURAS_GONZALO/).

### Natalia Alejo Pérez → [cuaderno](cuadernos/natalia-alejo.md)
- Inventario con registro de sesión completo (`script`) y matriz de trazabilidad de cada dato.
- Escaneo de la .10 (IPMI) a menor velocidad y comprobación de que los `open|filtered` de la .3 y la
  .7 eran ruido.
- Sesión nula de Samba en la .8: cuentas, recursos y el fichero `access.txt` de `myshare`, con un
  token JWT caducado que contiene el correo `satriani7@eseemeb.dl` (C-10).
- Intento de obtener la versión de Samba con `smb-os-discovery`, que dejó SambaCry sin confirmar.
- Consulta de NVD, EPSS y KEV, incluido el KEV del aviso de la noticia.
- Evidencias en [evidencias/EVIDENCIAS_NATALIA/](evidencias/EVIDENCIAS_NATALIA/).

### Pablo Ostenero Reyes → [cuaderno](cuadernos/pablo-ostenero-reyes.md)
- Inventario completo, con la .3 como equipo delicado, y la misma comparación con la hoja del cliente.
- Enumeración de todos los servicios y búsqueda de cuentas, con el mismo resultado (`info@dockerlabs.lab`).
- Fichas de NVD de CVE-2024-38475 y CVE-2026-119618, evidencias de V-14 y V-15.
- Descartes razonados de varios CVE propuestos por `vulners`: CVE-2021-28169, CVE-2025-26465,
  CVE-2023-28531, CVE-2026-60002, SambaCry y Zerologon.
- regreSSHion en la .6 (V-04), comprobado también con el tracker de Debian.
- EPSS del aviso de la noticia del 2026-11-23: 0,955, frente al 0,189 del 2026-11-20 (V-13).
- Evidencias en [evidencias/EVIDENCIAS_PABLO/](evidencias/EVIDENCIAS_PABLO/) y capturas en
  [imagenes/CAPTURAS_PABLO/](imagenes/CAPTURAS_PABLO/).

## Relación con la evaluación (RA3.b)

En esta sección «hicimos» indica algo que hicimos los cuatro; cuando algo lo hizo solo una persona,
se indica su nombre.

### Respeto de las reglas de compromiso
Todo el trabajo es identificación no intrusiva dentro de `172.17.0.0/24`:
- Nadie ha explotado nada, probado credenciales (tampoco las de fábrica) ni hecho fuerza bruta.
- Los scripts de nmap se limitaron a categorías seguras, excluyendo `intrusive`, `exploit`, `dos`,
  `brute`, `malware` y `auth`. Antes de usar cada script suelto comprobamos sus categorías.
- Nadie usó herramientas que exploten un fallo: por ejemplo, no se pidió a IPMI ningún hash
  (`ipmi-dumphashes`), no se lanzó ningún script contra el FTP de vsftpd y no se enviaron
  mensajes ni suscripciones al broker ActiveMQ (la conexión STOMP de Gonzalo se cortó tras el
  saludo).
- La entrada de la hoja del cliente que queda fuera del alcance (172.17.1.6) no la tocó nadie.
- Ningún equipo se cayó: Luis Miguel y Pablo vigilaron con `ping` el equipo que consideraron
  delicado, sin pérdidas, y Natalia comprobó al terminar que seguían activos los ocho equipos.
- **Diferencias de criterio**, explicadas en los entregables: Natalia y Gonzalo usaron la sesión
  nula de SMB (sin contraseña) y Gonzalo usó `-O`; Luis Miguel y Pablo no, para no acceder con
  credenciales vacías ni cargar el equipo delicado. Lo que se obtuvo así se recoge con su nombre.
- La única vez que nmap lanzó por su cuenta un script no pedido (`mqtt-subscribe`, al usar `-sV` en
  la copia de Luis Miguel) está explicada en el inventario y en el registro.

### Inventario de equipos → [inventario.md](inventario.md), Parte 1
- **Descubrimiento con técnicas activas, sin fiarnos de la hoja del cliente.** Los cuatro hicimos
  un barrido sin escanear puertos. Luis Miguel y Pablo combinaron ICMP, TCP y UDP y lo contrastaron
  con un barrido ARP usando `diff`; Gonzalo usó ARP. Resultado común: **8 equipos vivos**
  (172.17.0.3 a 172.17.0.10).
- **Mapa completo de puertos.** Los cuatro escaneamos los 65 535 puertos TCP, no solo los
  habituales. Gracias a eso apareció la mensajería real del cliente: un broker ActiveMQ en 7
  puertos altos de la .5 que un escaneo de los puertos comunes no veía (Natalia lo comprobó
  comparando su escaneo inicial con el completo).
- **UDP.** Luis Miguel y Gonzalo revisaron los 1000 puertos más comunes y Natalia y Pablo los 100
  más comunes. Los cuatro obtuvimos lo mismo: 137/udp en la .8 y 623/udp en la .10. Los
  `open|filtered` no se dan por abiertos: Natalia vio que los de la .3 y la .7 desaparecían al
  repetir el escaneo, y Luis Miguel que el 69/udp de la .7 salía cerrado al ir más despacio.
- **Servicio y versión de cada puerto abierto** con `-sV`, solo sobre los puertos abiertos: 24
  puertos TCP y 2 UDP, iguales en las cuatro copias. El sistema se dedujo de los banners y, además,
  Gonzalo lo confirmó con `-O` (Linux en los ocho equipos).
- **Equipo antiguo y delicado.** Cada uno lo buscó con su propio criterio antes del escaneo
  completo: Luis Miguel eligió la .7 (OpenSSH 7.7 sin distribución), Pablo la .3 (vsftpd 2.3.4) y
  Natalia escaneó la .10 (IPMI) más despacio. Los tres criterios están explicados en el inventario.
- **Corrección de la hoja del cliente** ([apartado](inventario.md#correcciones-al-inventario-del-cliente)):
  Luis Miguel y Pablo llegaron por separado a las mismas cifras, y Natalia confirmó las mismas IP
  sin respuesta: **7 entradas sobran**, **2 tienen datos erróneos** (la .9 y la .10), 1 queda sin
  comprobar por estar fuera del alcance y **faltan 6 equipos vivos**, entre ellos los que prestan
  de verdad el FTP, el portal, la mensajería y las carpetas compartidas.
- Cada decisión (qué escanear, a qué velocidad y por qué no se hizo otra cosa) está justificada en
  la tabla «Decisiones de la Parte 1 y por qué».

### Enumeración de servicios y cuentas → [inventario.md](inventario.md), Parte 2
- **Técnica adecuada a cada servicio, sin autenticarnos:** banners con `nc`, cabeceras HTTP y
  portada con `curl` (y `whatweb` en su nivel menos agresivo), certificado TLS con `openssl`,
  negociación SSH (`ssh2-enum-algos`, `ssh-hostkey`), nombres NetBIOS (`nbstat`, `nmblookup`) y
  versión de IPMI (`ipmi-version`). Los cuatro usamos técnicas equivalentes.
- **Lo que obtuvimos entre todos:** Jenkins 2.441 en la .6 por la cabecera `X-Jenkins` (nmap solo
  veía «Jetty»); la consola de ActiveMQ en el 8161 pidiendo contraseña; el certificado autofirmado
  y caducado del portal; el nombre SAMBASERVER y el grupo ESEEMEB.DL; e IPMI 2.0 con autenticación
  `null` anunciada en la .10.
- **Aportaciones individuales:**
  - Luis Miguel: la versión exacta de ActiveMQ (5.15.15) en el `WireFormatInfo` del 61616, la traza
    Java de STOMP, la firma SMB no obligatoria y los algoritmos SSH débiles.
  - Gonzalo: STOMP acepta conexiones sin credenciales; Tomcat anuncia sus rutas de administración;
    y la web de la .10 cita CVE-2013-4786.
  - Natalia y Gonzalo: con la sesión nula de Samba, las cuentas y los recursos de la .8; Natalia,
    además, el fichero `access.txt` de `myshare` con un token JWT caducado.
- **Cuentas de usuario** ([apartado](inventario.md#cuentas-de-usuario-descubiertas)): el correo
  `info@dockerlabs.lab` y el autor `Devcrud` de la web de la .5 (Luis Miguel y Pablo, cada uno con
  su búsqueda revisada a mano); las cuentas de Samba de la .8 (`usuario1` a `usuario3`,
  `satriani7`, `administrador`, `nobody` y `ubuntu`) y `satriani7@eseemeb.dl` (Natalia y
  Gonzalo). Se explica también por qué `ejemplo@correo.com`, `SAMBASERVER<03>` o `ESEEMEB.DL`
  **no** son cuentas.
- **Limitaciones documentadas:** la versión exacta de Samba no se conoce (tampoco con la sesión
  nula de Natalia), y las consolas de ActiveMQ, Jenkins y los formularios de acceso piden
  credenciales. Nadie las probó.

### Vulnerabilidades caracterizadas y priorizadas → [registro-vulns.md](registro-vulns.md)
- **De la versión al CVE con contraste:** sacamos candidatos con `vulners` y `searchsploit` (solo
  para listar), los verificamos en NVD (`cpeMatch`) y, en el caso de Luis Miguel y Pablo, en los
  trackers de Debian y Ubuntu para detectar backports. Luis Miguel añadió a mano Jenkins e IPMI,
  que las herramientas no veían.
- **15 hallazgos, cada uno con su ficha:** CVE con explicación, CWE, técnica ATT&CK (T1190 para lo
  que da la cara al exterior y T1210 para lo interno), lo observado, por qué se sospecha,
  evidencias, limitaciones y qué queda por comprobar sin explotar. La tabla «Contraste con el
  trabajo del grupo» del registro dice quién registró cada uno:
  - Comunes a todos: vsftpd (V-01), ActiveMQ (V-02) y «sshole» (V-13); Ghostcat (V-03), Jenkins
    (V-08), IPMI (V-12) y el de enumeración de usuarios SSH (V-06) los registramos varios.
  - Aportados por Gonzalo y Pablo: `mod_rewrite` de Apache (V-14, en KEV) y `mod_http2` (V-15).
- **Descarte de falsos positivos**
  ([apartado](registro-vulns.md#candidatos-descartados-falsos-positivos)), cada uno con su motivo:
  backports de Debian y Ubuntu (regreSSHion en la .8 y la .9, Terrapin en la .4, .6 y .9), fallos
  que solo afectan al cliente SSH o a Windows, Samba sin versión evaluable y, aportados por Pablo,
  el ConcatServlet de Jetty, SambaCry y Zerologon. Luis Miguel comprobó además que el Apache 2.4.68
  de la .9 es una versión real antes de usarla para descartar.
- **Priorización con datos, no por intuición** ([apartado](registro-vulns.md#orden-de-prioridad)):
  - Cada ficha tiene CVSS (versión, vector e impacto en C/I/A), EPSS y KEV con uso en ransomware,
    con fuente y fecha de consulta (y quién la hizo, cuando el dato viene de otro integrante).
  - El orden aplica primero KEV, después el tramo de CVSS y, dentro de cada tramo, EPSS y la
    solidez de la evidencia antes que la importancia del equipo. Cada fila justifica por qué va
    antes que la siguiente.
  - Resultado: 6 hallazgos en KEV, 2 de ellos usados en ransomware (ActiveMQ y Jenkins), que
    encabezan la lista. El sexto, `mod_rewrite` de Apache, salió al contrastar el trabajo del grupo.
  - Ejemplo de KEV por encima del CVSS: «sshole» (V-13, CVSS 8,1) va antes que la puerta trasera de
    vsftpd (V-01, CVSS 9,8) porque CISA confirma que ya se está explotando.
- **Respuesta al aviso de la noticia** (CVE-2026-123158, «sshole»): los cuatro lo contrastamos con
  los cinco equipos con OpenSSH. En los cuatro Debian y Ubuntu, «según lo observado, no» (el fallo
  exige musl libc sin PAM); en la .7, «no lo podemos descartar». Gonzalo aportó que la .7 es Linux
  (`-O`) y Pablo que el EPSS subió de 0,189 a 0,955 en tres días, lo que refuerza la urgencia.
- **Hallazgos de configuración sin CVE** (C-01 a C-12; C-10 a C-12 aportados por Natalia y
  Gonzalo), aparte porque no se puntúan con CVSS, EPSS ni KEV.
- **Informe para el cliente** ([informe-cliente.md](informe-cliente.md)), en lenguaje no técnico:
  tres correcciones prioritarias, tres medidas urgentes y baratas (vsftpd, acceso por contraseña
  del equipo antiguo y acceso anónimo a las carpetas compartidas), qué otros fallos cubren esas
  mismas actualizaciones y la respuesta a la noticia, separando lo que sostienen las evidencias de
  lo que queda pendiente.

### Cuadernos y evidencias → [Cuadernos del grupo](#cuadernos-del-grupo)
- Cada integrante tiene su cuaderno individual con las cinco notas de cada comprobación: cuándo,
  objetivo y que está en alcance, qué se hizo (con el comando exacto), qué salió y siguiente paso.
- Cada dato de los entregables cita el fichero de salida o la captura de quien lo obtuvo, en
  `evidencias/EVIDENCIAS_<NOMBRE>/` e `imagenes/CAPTURAS_<NOMBRE>/`.
- Los cuadernos recogen también los errores y las rectificaciones de cada uno, para poder seguir
  cómo se llegó a cada conclusión.

## Cuadernos del grupo

Cada integrante ha trabajado sobre su propia red y mantiene su propio cuaderno.

| Integrante | Cuaderno | Evidencias | Capturas |
|---|---|---|---|
| Luis Miguel Gomila Domínguez | [cuaderno](cuadernos/luis-miguel-gomila-dominguez.md) | [EVIDENCIAS_LUISMI](evidencias/EVIDENCIAS_LUISMI/) | [CAPTURAS_LUISMI](imagenes/CAPTURAS_LUISMI/) |
| Gonzalo García Vega | [cuaderno](cuadernos/gonzalo-garciavega-1.md) | [EVIDENCIAS_GONZALO](evidencias/EVIDENCIAS_GONZALO/) | [CAPTURAS_GONZALO](imagenes/CAPTURAS_GONZALO/) |
| Natalia Alejo Pérez | [cuaderno](cuadernos/natalia-alejo.md) | [EVIDENCIAS_NATALIA](evidencias/EVIDENCIAS_NATALIA/) | dentro de sus evidencias |
| Pablo Ostenero Reyes | [cuaderno](cuadernos/pablo-ostenero-reyes.md) | [EVIDENCIAS_PABLO](evidencias/EVIDENCIAS_PABLO/) | [CAPTURAS_PABLO](imagenes/CAPTURAS_PABLO/) |

## Evidencias y capturas

**Nota sobre las evidencias:** el fichero `access.txt` que Natalia leyó en el recurso `myshare` de la
172.17.0.8 no se publica en el repositorio. En su registro de sesión
([`registro_sesion_terminal.log`](evidencias/EVIDENCIAS_NATALIA/registro_sesion_terminal.log)) la
firma del token aparece sustituida por `[FIRMA-JWT-REDACTADA]`; solo queda visible su contenido
decodificado (correo, rol y fechas), que es lo que se cita en los entregables.

- `evidencias/EVIDENCIAS_<NOMBRE>/`: salidas de las herramientas de cada integrante.
- `imagenes/CAPTURAS_<NOMBRE>/`: capturas de pantalla de cada integrante.
- Las de Luis Miguel están ordenadas por parte: [evidencias/EVIDENCIAS_LUISMI/](evidencias/EVIDENCIAS_LUISMI/)
  (p1 a p4) e [imagenes/CAPTURAS_LUISMI/](imagenes/CAPTURAS_LUISMI/) (prefijos p0 a p4).
