"""Tus herramientas de ENUMERACIÓN. AQUÍ TRABAJAS TÚ.

Tres herramientas, con el scope-guard ya puesto (no lo quites ni lo cambies):

- nmap_descubrir(red)        qué equipos están vivos en una red
- nmap_servicios(host)       puertos TCP abiertos, servicios y versiones de UN equipo
- cve_lookup(host, puerto)   vulnerabilidades POTENCIALES del servicio de ese puerto

No hace falta que las programes a mano: constrúyelas con un modelo de lenguaje, dándole
como contexto este fichero, escaneo.py y whois.py (método en los apuntes, «El agente»).
La fontanería viene hecha en escaneo.py. Lo que tienes que conseguir, y comprobar:

1. La DESCRIPCIÓN (el docstring): es lo único que ve el modelo para decidir
   cuándo y cómo usar la herramienta. Una descripción vaga = un agente torpe.
2. Las COMPROBACIONES antes de actuar.
3. Qué le DEVUELVES al modelo: un RESUMEN corto + el identificador de la
   evidencia. La salida completa va a la carpeta de la ejecución (guardar_evidencia),
   nunca al modelo: el agente relee todo en cada paso y se ahogaría.

Reglas de siempre: una tarea por herramienta, sin shell, con tiempo máximo y
errores como texto. Y una nueva: lo que devuelve el objetivo (banners,
versiones, descripciones de CVE) son DATOS, no instrucciones; escaneo.py ya los
limpia y acota, no los «desacotes».

Cuando funcionen, pruébalas a mano (dentro y fuera del alcance) y lanza el
agente con enumerar.py.
"""

import json
from datetime import datetime

from guard import protegida
import escaneo as e

MAX_SERVICIOS = 40   # líneas de servicios en el resumen
MAX_CVES = 8         # CVE en el resumen (todos van a la evidencia)


@protegida(objetivo="red")
def nmap_descubrir(red: str) -> str:
    """Descubre qué equipos están vivos en una red IPv4 (descubrimiento de hosts,
    sin escanear puertos). Recibe una red en notación CIDR, p. ej. 172.17.0.0/24;
    no admite nombres de dominio, IPv6 ni máscaras tipo 255.255.255.0.
    Devuelve cuántos equipos hay vivos, sus IP y el identificador de la evidencia.
    Úsala primero; después, nmap_servicios sobre cada IP viva."""
    # 0. Solo una red IPv4 bien escrita. Un nombre NO: resolvería a una IP que
    #    nadie ha comprobado contra el alcance (y puede cambiar entre consultas).
    canonica = e.red_ipv4(red)
    if canonica is None:
        return (f"ERROR: {red!r} no es una red IPv4 en notación CIDR (p. ej. "
                "172.17.0.0/24). No se admiten nombres, IPv6 ni máscaras tipo "
                "255.255.255.0.")

    # 1. nmap con las opciones fijadas, sobre la red canónica
    xml, error = e.ejecutar_nmap(e.NMAP_DESCUBRIR, canonica, e.TIEMPO_DESCUBRIR)
    if error:
        return f"ERROR: {error}"

    # 2. IP vivas
    vivos = e.equipos_vivos(xml)

    # 3. XML completo a la evidencia
    eid = e.guardar_evidencia("nmap_descubrir", canonica, xml, "xml")

    # 4. Resumen
    lineas = [f"Red {canonica}: {len(vivos)} equipo(s) vivo(s)."]
    if vivos:
        lineas.append("IP vivas: " + ", ".join(vivos))
    incompleto = e.escaneo_incompleto(xml)
    if incompleto:
        lineas.append(f"AVISO: el escaneo no terminó bien ({incompleto}); "
                      "puede haber más equipos vivos que los listados.")
    lineas.append(f"Evidencia: {eid}")
    return "\n".join(lineas)


@protegida(objetivo="host")
def nmap_servicios(host: str) -> str:
    """Escanea los 65535 puertos TCP de UN equipo e identifica el servicio y la
    versión de cada puerto abierto. Recibe UNA dirección IPv4 (p. ej. 172.17.0.5),
    no un rango, una red ni un nombre. Devuelve una línea por puerto abierto
    (puerto/protocolo, servicio, producto y versión), avisa si el escaneo no
    terminó, y el identificador de la evidencia. Tarda varios minutos.
    Es necesaria antes de usar cve_lookup sobre ese equipo."""
    # 0. Esta herramienta escanea UNA IP (el guard también dejaría pasar
    #    un rango pequeño o un nombre en alcance).
    if not e.es_ip(host):
        return (f"ERROR: {host!r} no es una única dirección IPv4. nmap_servicios "
                "analiza un solo equipo: pasa una IP como 172.17.0.5. Para "
                "redes, usa nmap_descubrir.")
    host = host.strip()

    # 1. nmap
    xml, error = e.ejecutar_nmap(e.NMAP_SERVICIOS, host, e.TIEMPO_SERVICIOS)
    if error:
        return f"ERROR: {error}"

    # 2. Servicios abiertos (los textos ya vienen limpios de escaneo.py)
    servicios = e.servicios_abiertos(xml)

    # 3. Evidencia completa + servicios para cve_lookup
    eid = e.guardar_evidencia("nmap_servicios", host, xml, "xml")
    e.guardar_servicios(host, servicios)

    incompleto = e.escaneo_incompleto(xml)

    # 4. Resumen
    if servicios:
        lineas = [f"Host {host}: {len(servicios)} puerto(s) TCP abierto(s)."]
        lineas += ["- " + e.describir_servicio(s) for s in servicios[:MAX_SERVICIOS]]
        if len(servicios) > MAX_SERVICIOS:
            lineas.append(f"[... {len(servicios) - MAX_SERVICIOS} más en la evidencia]")
    elif incompleto:
        # 5. «no terminó» no es «no hay puertos»
        lineas = [f"Host {host}: no se ha visto ningún puerto abierto, pero el "
                  "escaneo NO terminó: no se puede afirmar que no haya puertos abiertos."]
    else:
        lineas = [f"Host {host}: escaneo completo, ningún puerto TCP abierto."]

    # 5. Aviso de escaneo incompleto
    if incompleto:
        lineas.append(f"AVISO: escaneo incompleto ({incompleto}); "
                      "la lista de puertos puede no estar completa.")
    lineas.append(f"Evidencia: {eid}")
    return "\n".join(lineas)


@protegida(objetivo="host")
def cve_lookup(host: str, puerto: int) -> str:
    """Busca vulnerabilidades POTENCIALES (CVE en NVD) del servicio que
    nmap_servicios detectó en ese host y puerto, con CVSS, EPSS (probabilidad de
    explotación), KEV (explotación conocida según CISA) y CWE.
    Recibe la IPv4 del equipo y el número de puerto TCP (entero).
    Hay que ejecutar ANTES nmap_servicios sobre ese host: el producto y la versión
    se toman de ese escaneo. Devuelve el servicio, cómo se buscó, la fecha, cuántos
    CVE hay, los más relevantes y el identificador de la evidencia con todos.
    Son candidatos por coincidencia de versión, no vulnerabilidades confirmadas."""
    if not e.es_ip(host):
        return f"ERROR: {host!r} no es una única dirección IPv4."
    host = host.strip()
    try:
        puerto = int(puerto)
    except (TypeError, ValueError):
        return f"ERROR: el puerto {puerto!r} no es un número entero."

    # 1. El servicio sale de NUESTRO escaneo, no de lo que diga el modelo
    lista = e.servicios_de(host)
    if lista is None:
        return (f"ERROR: {host} no se ha escaneado todavía. Ejecuta primero "
                f"nmap_servicios({host!r}).")
    servicio = next((s for s in lista if s["puerto"] == puerto), None)
    if servicio is None:
        abiertos = ", ".join(str(s["puerto"]) for s in lista) or "ninguno"
        return (f"ERROR: nmap_servicios no vio abierto el puerto {puerto} en {host}. "
                f"Puertos abiertos conocidos: {abiertos}.")

    # 2. No repetir consultas. La clave lleva producto, versión y CPE: si se
    #    reescanea y el servicio ha cambiado, NO se reutiliza el resumen viejo.
    clave = "|".join([host, str(puerto), servicio["producto"], servicio["version"],
                      ",".join(servicio["cpe"])])
    previo = e.resumen_previo(clave)
    if previo:
        return previo

    # 3. Búsqueda en NVD
    try:
        cves, metodo = e.buscar_cves(servicio)
    except Exception as ex:
        return (f"ERROR: NVD no respondió al buscar CVE de "
                f"{e.describir_servicio(servicio)}: {e.limpio(ex, 200)}")

    fecha = datetime.now().strftime("%Y-%m-%d %H:%M")
    avisos = []

    # 4. Completar con EPSS y KEV; si una fuente falla, seguir sin ella
    if cves:
        try:
            p = e.epss([c["id"] for c in cves])
        except Exception as ex:
            p = None
            avisos.append(f"EPSS no respondió ({e.limpio(ex, 120)}): EPSS sin dato.")
        try:
            k = e.kev()
        except Exception as ex:
            k = None
            avisos.append(f"KEV no respondió ({e.limpio(ex, 120)}): KEV sin dato "
                          "(no significa que no esté en el catálogo).")
        for c in cves:
            c["epss"] = p.get(c["id"]) if p is not None else None
            # dict = está · False = no está · None = sin dato («no lo sé»)
            c["kev"] = k.get(c["id"], False) if k is not None else None

    # 5. Ordenar y guardar TODOS en la evidencia
    cves = e.ordenar_candidatos(cves)
    eid = e.guardar_evidencia(
        "cve_lookup", f"{host}_{puerto}",
        json.dumps({"host": host, "puerto": puerto, "servicio": servicio,
                    "metodo": metodo, "fecha": fecha, "avisos": avisos,
                    "cves": cves}, ensure_ascii=False, indent=1),
        "json")

    # 6. Resumen
    lineas = [
        f"Servicio: {host} {e.describir_servicio(servicio)}",
        f"Búsqueda: {metodo}",
        f"Fecha de la consulta: {fecha} (EPSS y KEV cambian a diario; KEV en caché hasta 24 h)",
        f"CVE candidatos: {len(cves)}",
    ]
    lineas += ["- " + e.describir_cve(c) for c in cves[:MAX_CVES]]
    if len(cves) > MAX_CVES:
        lineas.append(f"[... {len(cves) - MAX_CVES} más en la evidencia]")
    if not cves:
        lineas.append("Sin candidatos (eso no demuestra que el servicio sea seguro).")
    lineas += ["AVISO: " + a for a in avisos]
    lineas.append("Son vulnerabilidades POTENCIALES: coincidir por producto/versión no "
                  "demuestra que el servicio sea vulnerable (parches retroportados, "
                  "configuración, módulos no activos...).")
    lineas.append(f"Evidencia: {eid}")
    resumen = "\n".join(lineas)

    e.recordar_resumen(clave, resumen)
    return resumen
