# Mapping the Maze - Gadir Logística, S.L.

**Alumno:** Luis Miguel Gomila Domínguez
**Grupo:** Luis Miguel Gomila Domínguez, Gonzalo <Apellido>, Natalia <Apellido>, Pablo Ostenero
**Alcance autorizado:** `172.17.0.0/24` (ver [scope.txt](scope.txt))
**Tipo de trabajo:** identificación activa no intrusiva, sin explotación

Todo el trabajo de este repositorio lo he realizado sobre mi propia copia de la red del cliente.
Cada dato de los documentos se puede rastrear hasta un comando de [mi cuaderno](cuadernos/luis-miguel-gomila-dominguez.md),
con su salida en [evidencias/](evidencias/) y su captura en [imagenes/](imagenes/).

## Documentos

| Parte | Documento |
|---|---|
| 1. Descubrir y mapear | [inventario.md](inventario.md) |
| 2. Enumerar sin autenticar | [inventario.md](inventario.md) (apartado Parte 2) |
| 3. De la versión al CVE | [registro-vulns.md](registro-vulns.md) |
| 4. Priorizar e informar | [registro-vulns.md](registro-vulns.md), [informe-cliente.md](informe-cliente.md) |

## Relación con la evaluación (RA3.b)

### Respeto de las reglas de compromiso
Todo el trabajo es identificación no intrusiva dentro de `172.17.0.0/24`:
- No se ha explotado nada, ni se han probado credenciales (tampoco las de fábrica), ni se ha hecho
  fuerza bruta.
- Los scripts de nmap se limitaron a los que son a la vez `default` y `safe`, excluyendo
  expresamente `intrusive`, `exploit`, `dos`, `brute`, `malware`, `auth`, `broadcast` y
  `external`. Antes de usar cada script suelto se comprobaron sus categorías.
- Se descartaron herramientas que, aun pareciendo inofensivas, inician sesión: `smb-os-discovery`
  abre una sesión anónima y `ipmi-dumphashes` explotaría el fallo de RAKP.
- La única vez que nmap lanzó por su cuenta un script no pedido (`mqtt-subscribe`, al usar `-sV`)
  está explicada en el inventario y en el registro.
- La entrada de la hoja del cliente que queda fuera del alcance (172.17.1.6) no se ha tocado.

### Inventario de equipos → [inventario.md](inventario.md), Parte 1
- **Descubrimiento con técnicas activas, sin fiarme de la hoja del cliente.** Hice un barrido
  combinando ICMP, TCP SYN/ACK y UDP, y después otro con ARP. Los comparé con `diff`: en la misma
  red un equipo puede ignorar ICMP, TCP y UDP, pero no ARP. Que coincidan demuestra que no hay
  equipos ocultos. Resultado: **8 equipos vivos** (172.17.0.3 a 172.17.0.10).
- **Mapa completo de puertos.** Escaneé los 65 535 puertos TCP de cada equipo, no solo los
  habituales. Gracias a eso apareció la mensajería real del cliente: un broker ActiveMQ en 7
  puertos altos de la .5 que la pasada de los 100 puertos más comunes no veía. En UDP revisé los
  1000 puertos más comunes. Solo los que respondieron cuentan como abiertos (137/udp en la .8 y
  623/udp en la .10); los `open|filtered` no se dan por abiertos, y la propia red lo confirmó (el
  69/udp de la .7 resultó estar cerrado al repetirlo más despacio).
- **Servicio y versión de cada puerto abierto** con `-sV`, solo sobre los puertos ya encontrados
  abiertos. En total, 24 puertos TCP y 2 UDP, con su producto y versión. El sistema operativo se
  dedujo de los banners, sin `-O`, para no enviar tráfico innecesario.
- **Equipo antiguo y delicado.** Antes del escaneo completo hice una pasada suave para localizarlo.
  Lo identifiqué como la 172.17.0.7 por la antigüedad de su software (OpenSSH 7.7 de 2018, sin
  paquete de distribución). Lo escaneé con `--max-rate 30` en TCP y con `-T2` y
  `--max-rate 10` en UDP, con un solo reintento y vigilado con `ping`. No se cayó ni perdió
  paquetes.
- **Corrección de la hoja del cliente** ([apartado](inventario.md#correcciones-al-inventario-del-cliente)):
  de sus 10 entradas, **7 sobran** (no responden ni a ARP), **2 tienen datos erróneos** (la .9 y la
  .10 existen, pero con otro sistema y otros servicios) y 1 queda sin comprobar por estar fuera del
  alcance. Además le **faltan 6 equipos vivos**, entre ellos los que prestan de verdad el FTP, el
  portal, la mensajería y las carpetas compartidas. También se señala el nombre duplicado
  SRV-PORTAL01.
- Cada decisión (qué escanear, a qué velocidad y por qué no se hizo otra cosa) está justificada en
  la tabla «Decisiones de la Parte 1 y por qué».

### Enumeración de servicios y cuentas → [inventario.md](inventario.md), Parte 2
- **Técnica adecuada a cada servicio, sin autenticarme:**
  - Banners con `nc` sin enviar datos.
  - Cabeceras HTTP, portada y `robots.txt` con `curl`, y `whatweb` en su nivel menos agresivo.
  - Certificado TLS con `openssl`.
  - Negociación SSH (`ssh2-enum-algos`, `ssh-hostkey`).
  - Negociación SMB y nombres NetBIOS (`smb-protocols`, `smb2-security-mode`, `nbstat`,
    `nmblookup`).
  - Versión de IPMI (`ipmi-version`).
- **Lo que se obtuvo, incluidos puertos altos y UDP:**
  - Jenkins 2.441 en la .6, gracias a la cabecera `X-Jenkins`; nmap solo veía «Jetty».
  - La versión exacta de ActiveMQ (5.15.15), anunciada por el propio broker en su `WireFormatInfo`
    del puerto 61616.
  - La traza Java que devuelve STOMP (61613).
  - El certificado autofirmado y caducado del portal.
  - En SMB, la firma no es obligatoria; nombre del equipo SAMBASERVER y grupo de trabajo
    ESEEMEB.DL por NetBIOS (137/udp).
  - IPMI 2.0 con autenticación `null` anunciada (623/udp).
  - Algoritmos SSH débiles en los equipos antiguos.
- **Cuentas de usuario** ([apartado](inventario.md#cuentas-de-usuario-descubiertas)): el correo
  `info@dockerlabs.lab` y el autor `Devcrud` de la web de la .5. Busqué con `grep` todo lo que
  pareciera una cuenta en las evidencias y revisé a mano cada candidato. Explico por qué
  `ejemplo@correo.com`, `SAMBASERVER<03>` o `ESEEMEB.DL` **no** son cuentas.
- **Limitaciones documentadas:** qué no se pudo obtener y por qué. Por ejemplo, los recursos y
  usuarios de Samba exigirían una sesión nula, y las consolas de ActiveMQ, Jenkins y los
  formularios de acceso piden credenciales. No se intentó ninguno.

### Vulnerabilidades caracterizadas y priorizadas → [registro-vulns.md](registro-vulns.md)
- **De la versión al CVE con contraste:**
  1. Saqué los candidatos con el script `vulners` de nmap y con `searchsploit`, en este último
     solo para listar, sin abrir ni ejecutar nada.
  2. Verifiqué cada uno en NVD (rango de versiones afectadas, campo `cpeMatch`) y en los trackers
     de seguridad de Debian y Ubuntu, para detectar parches aplicados sin cambiar el número de
     versión (backports).
  3. Añadí a mano lo que las herramientas no veían: Jenkins, porque nmap no lo identificaba, e
     IPMI, porque `vulners` solo revisa TCP.
- **12 hallazgos, cada uno con su ficha:**
  - CVE con explicación.
  - CWE, la que asigna NVD (o señalada como propia cuando NVD no da una concreta).
  - Técnica ATT&CK, con una regla única: T1190 para lo que da la cara al exterior y T1210 para los
    servicios internos.
  - Lo observado, por qué se sospecha, evidencias y capturas, limitaciones y qué queda pendiente
    de comprobar sin explotar.
- **Descarte de falsos positivos** ([apartado](registro-vulns.md#candidatos-descartados-falsos-positivos)),
  cada uno con su motivo:
  - regreSSHion en la .8 y la .9, y Terrapin en la .4, .6 y .9: ya parcheados por la distribución,
    porque la revisión del paquete es posterior a la del parche.
  - CVE-2024-50379: solo afecta a Windows.
  - CVE-2023-38408: afecta al cliente SSH, no al servidor.
  - Más de 300 CVE de Samba: la versión «4» no permite evaluar ningún rango.
  - Además comprobé que el Apache 2.4.68 de la .9 es una versión real que distribuye Debian 12, y
    no un banner falso, antes de usarlo para descartar.
- **Priorización con datos, no por intuición**
  ([apartado](registro-vulns.md#orden-de-prioridad)):
  - Cada ficha tiene CVSS (versión, vector e impacto en confidencialidad, integridad y
    disponibilidad), EPSS y KEV con uso en ransomware, con fuente y fecha de consulta.
  - El orden aplica primero KEV, después el tramo de CVSS y, dentro de cada tramo, EPSS y la
    solidez de la evidencia antes que la importancia del equipo.
  - Cada fila justifica por qué va antes que la siguiente. Hay casos en los que el orden contradice
    al CVSS, explicados uno a uno; por ejemplo, Apache, con CVSS 9,8, queda último porque depende
    de una configuración sin indicios y tiene el EPSS más bajo.
  - Resultado: 4 hallazgos en KEV, 2 de ellos usados en ransomware (ActiveMQ y Jenkins), que
    encabezan la lista.
- **Hallazgos de configuración sin CVE** (C-01 a C-09), recogidos aparte porque no se pueden
  puntuar con CVSS, EPSS ni KEV.
- **Informe para el cliente** ([informe-cliente.md](informe-cliente.md)) en lenguaje no técnico:
  - Las tres correcciones prioritarias y una medida urgente y barata para la puerta trasera de
    vsftpd.
  - Qué otros fallos quedan cubiertos por esas mismas actualizaciones.

### Cuaderno y evidencias → [mi cuaderno](cuadernos/luis-miguel-gomila-dominguez.md)
- Desde el primer comando, cada acción tiene sus cinco notas: cuándo (en UTC), objetivo y que está
  en alcance, qué hice (con el comando exacto), qué salió y siguiente paso. Al final de cada parte
  hay un resumen.
- Cada dato de los entregables cita su fichero de salida en [evidencias/](evidencias/), ordenado
  por parte (p1 a p4), y su captura en [imagenes/](imagenes/). Los comandos con su fecha y hora
  están en `evidencias/pN/historial-comandos.txt`.
- El cuaderno también recoge los errores y las rectificaciones: escaneos cancelados por lentos,
  el script lanzado sin pedirlo, la corrección de criterios de ATT&CK y del orden de prioridad.
  Así se puede seguir cómo se llegó a cada conclusión.

## Cuadernos del grupo

Cada integrante ha trabajado sobre su propia red y mantiene su propio cuaderno.

- [Luis Miguel Gomila Domínguez](cuadernos/luis-miguel-gomila-dominguez.md)
- [Gonzalo <Apellido>](cuadernos/gonzalo-<apellido>.md)
- [Natalia <Apellido>](cuadernos/natalia-<apellido>.md)
- [Pablo Ostenero](cuadernos/pablo-ostenero.md)

Las capturas y evidencias que citan los cuadernos de mis compañeros están en
`imagenes/<nombre>/` y `evidencias/<nombre>/`.

## Evidencias y capturas

- [evidencias/](evidencias/): salidas de todas mis herramientas, por parte (p1 a p4).
- [imagenes/](imagenes/): capturas de pantalla de cada comando, con el prefijo de su parte (p0 a p4).
