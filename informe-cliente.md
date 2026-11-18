# Informe de vulnerabilidades priorizado - Gadir Logística, S.L.

**Para:** Dirección de Gadir Logística, S.L.
**Fecha:** 2026-11-18
**Alcance:** red interna 172.17.0.0/24
**Tipo de revisión:** identificación no intrusiva. No se ha explotado ni modificado nada y
ningún servicio se ha interrumpido.

## 1. Resumen para la dirección

Hemos revisado su red interna y hemos encontrado **8 equipos activos** (su hoja de
inventario recogía 10, de los que solo 2 siguen en la red) y **12 vulnerabilidades
potenciales**. De ellas, **4 se están aprovechando ya por atacantes en el mundo real**, según
el catálogo de vulnerabilidades explotadas de la agencia de ciberseguridad de EE. UU. (CISA KEV),
y 2 de esas 4 se han usado en ataques de secuestro de datos (ransomware).

Con el presupuesto de este trimestre, recomendamos corregir primero estas tres:

1. **Mensajería con los operadores (172.17.0.5, programa Apache ActiveMQ 5.15.15)**: cualquiera
   que llegue a este equipo por la red podría tomar el control del servidor sin necesitar
   contraseña. Es un fallo usado en ataques de ransomware. Acción: actualizar ActiveMQ a la
   versión 5.18.3 o posterior (como mínimo 5.16.7), que corrige también el fallo de su consola
   web (prioridad 7).
2. **Servidor Jenkins (172.17.0.6, Jenkins 2.441, herramienta de automatización de tareas)**:
   un atacante sin contraseña podría leer ficheros del servidor, entre ellos claves y
   contraseñas guardadas. También se ha usado en ataques de ransomware. Acción: actualizar
   Jenkins a la versión 2.442 o posterior (o a la versión de soporte largo 2.426.3 o posterior).
3. **Aplicación web Java (172.17.0.4, Apache Tomcat 9.0.30)**: su conector interno AJP (puerto
   8009) está abierto a la red y permitiría leer ficheros de las aplicaciones, como su
   configuración con contraseñas. Acción: actualizar Tomcat a la versión 9.0.99 o posterior,
   que corrige también el fallo de prioridad 4 del mismo equipo, y cerrar el puerto 8009 a la
   red si no se usa.

## 2. Qué hay en su red

| Equipo | Para qué sirve | Servicios que ofrece a la red |
|---|---|---|
| 172.17.0.5 | Portal de clientes | Web en los puertos 80 y 443 (cifrada, con el certificado caducado desde abril de 2025) |
| 172.17.0.5 | Mensajería con operadores | Programa ActiveMQ en los puertos 1883, 5672, 61613, 61614 y 61616, y su consola web en el 8161 (pide contraseña). Además, en el puerto 38443 hay un servicio que no se ha podido identificar |
| 172.17.0.9 | Servidor de pruebas del antiguo informático | Web «en desarrollo» con página de acceso (puerto 80) y acceso remoto SSH (puerto 22) |
| 172.17.0.10 | Consola de gestión de servidores | Gestión remota IPMI (puerto 623/udp) y una web informativa (puerto 80) |
| 172.17.0.7 | Equipo antiguo | Solo acceso remoto SSH (puerto 22), con una versión de 2018 |
| 172.17.0.3 | Servidor FTP y web (no figuraba en su hoja) | Transferencia de ficheros FTP (puerto 21) y web por defecto (puerto 80) |
| 172.17.0.4 | Aplicación web Java (no figuraba en su hoja) | Tomcat en el puerto 8080, su conector interno AJP en el 8009 y acceso remoto SSH (22) |
| 172.17.0.6 | Servidor Jenkins (no figuraba en su hoja) | Jenkins en el puerto 8080 (pide contraseña) y acceso remoto SSH (22) |
| 172.17.0.8 | Servidor de ficheros (no figuraba en su hoja) | Carpetas compartidas Samba (puertos 139, 445 y 137/udp), web con página de acceso (80) y acceso remoto SSH (22) |

Su hoja de inventario no está al día: 7 equipos que ya no existen, 6 equipos que no aparecían
y 2 equipos con datos erróneos. Una entrada más (172.17.1.6) queda fuera de la red que nos
autorizaron a revisar y no la hemos comprobado. El detalle está en `inventario.md`.

## 3. Vulnerabilidades por orden de prioridad

| Prioridad | Equipo | Qué le pasa | Riesgo para el negocio | Qué hacer |
|---|---|---|---|---|
| 1 | 172.17.0.5, mensajería con operadores (ActiveMQ 5.15.15) | Un atacante sin contraseña podría ejecutar órdenes en el servidor. Está en el catálogo KEV, con uso en ransomware | Control del servidor de mensajería: lectura o alteración de los mensajes con los operadores y parada de la facturación | Actualizar ActiveMQ a la 5.18.3 o posterior (mínimo 5.16.7) |
| 2 | 172.17.0.6, Jenkins 2.441 | Un atacante sin contraseña podría leer ficheros del servidor. Está en el catálogo KEV, con uso en ransomware | Robo de las claves y contraseñas que guarda Jenkins, con las que podría saltar a otros equipos | Actualizar Jenkins a la 2.442 o posterior (o LTS 2.426.3 o posterior) |
| 3 | 172.17.0.4, Tomcat 9.0.30 (conector AJP, puerto 8009) | Un atacante podría leer ficheros de las aplicaciones a través del conector AJP abierto. Está en el catálogo KEV | Robo de la configuración de las aplicaciones, que suele incluir contraseñas de bases de datos | Actualizar Tomcat a la 9.0.99 o posterior y cerrar el puerto 8009 a la red si no se usa |
| 4 y siguientes | Para próximos trimestres | 4: Tomcat de la .4 (otro fallo en KEV, que se corrige con la misma actualización de la prioridad 3). 5: FTP de la .3 (vsftpd 2.3.4, versión con puerta trasera). 6: consola de gestión de la .10 (IPMI 2.0, permite obtener contraseñas cifradas). 7 a 12: consola de ActiveMQ, SSH de la .6, Jetty de la .5, equipo antiguo .7 y Apache de la .3, .5 y .8 | Variable según el equipo; el detalle está en `registro-vulns.md` | Ver cada ficha en `registro-vulns.md` |

**Por qué este orden.** No hemos ordenado solo por la nota de gravedad técnica (CVSS). Hemos
adelantado lo que los atacantes ya están usando (catálogo KEV) o tienen mucha probabilidad de
usar en el próximo mes (indicador EPSS), y lo que afecta a los equipos de los que depende la
facturación. Por eso un fallo de gravedad media pero explotado activamente aparece antes que
otro con nota más alta pero sin ataques conocidos.

## 4. Advertencias

- El equipo **172.17.0.7** es antiguo y delicado: cualquier prueba agresiva puede tumbarlo.
  Recomendamos planificar su sustitución y aislarlo del resto de la red.
- Hay hallazgos graves que **no hemos tocado**, como pedía el contrato, y que deberían
  confirmarse en una siguiente fase con su permiso: el FTP de la 172.17.0.3 (vsftpd 2.3.4, una
  versión distribuida con una puerta trasera; si se confirma, el equipo debe darse por
  comprometido), la mensajería ActiveMQ de la 172.17.0.5, el Jenkins de la 172.17.0.6, el
  conector AJP de Tomcat en la 172.17.0.4 y la consola de gestión IPMI de la 172.17.0.10, que
  anuncia entre sus métodos de acceso uno sin contraseña (`null`); no hemos comprobado si
  está activo.
- Todo lo indicado es **potencial**: se basa en las versiones observadas desde la red, no en
  haber atacado los equipos.

## 5. Respuesta a su consulta sobre la noticia (<CVE-del-aviso>)

**¿Les afecta?** <Probablemente sí / No podemos descartarlo / Según lo observado, no>.

- **Qué es:** <producto afectado, qué permite hacer al atacante y desde cuándo se explota>.
  Gravedad CVSS <x>; probabilidad de explotación EPSS <y>; <figura / no figura> en el
  catálogo KEV de CISA <con / sin uso en ransomware>.
- **Lo que podemos sostener con nuestras pruebas:** <«en el equipo 172.17.0.n funciona
  <producto y versión>, que está dentro de las versiones afectadas» / «ningún equipo de su red
  muestra ese producto»>. Evidencia: `<fichero>`.
- **Lo que queda pendiente de comprobar:** <la versión exacta no se ve desde la red / podría
  estar parcheado por el fabricante sin cambiar el número / equipos apagados durante la
  revisión / configuración interna>.
- **Recomendación:** <parchear de inmediato / vigilar / no requiere acción>.

![Comprobación del aviso contra nuestro inventario](imagenes/p4-04-aviso.png)

## 6. Fuentes y fecha

NVD, FIRST EPSS, CISA KEV, MITRE CWE y MITRE ATT&CK, consultados el 2026-11-18 (valores de EPSS del 2026-11-17 y catálogo KEV
versión 2026.11.17).
El detalle técnico está en `registro-vulns.md` y en los cuadernos de trabajo.
