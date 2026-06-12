#!/usr/bin/env python3
"""
DNSSEC Analyzer — MA2002B Seguridad en redes informáticas
Tecnológico de Monterrey — A00841920

Analiza registros DNSKEY, RRSIG, NSEC/NSEC3/NSEC3PARAM y DS para verificar
que los dominios cumplan con los RFCs de DNSSEC (RFC 4033-4035, 5155, 6840).

Dominios analizados (10): mezcla de dominios con DNSSEC completo, parcial y sin él.
"""

import sys
import json
import hashlib
import struct
from datetime import datetime, timezone
from typing import Optional

import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdata
import dns.name
import dns.dnssec
import dns.flags
import dns.rrset

# ─────────────────────────────────────────────────────────────────────────────
# Configuración
# ─────────────────────────────────────────────────────────────────────────────

NAMESERVER = "8.8.8.8"       # Resolver con validación DNSSEC
TIMEOUT    = 6               # segundos por query

# Dominios a analizar (5–10 requeridos)
# Incluye dominios con DNSSEC completo, parcial e inexistente para comparar.
DOMAINS = [
    'unam.mx',
    'gob.mx',
    'sat.gob.mx',
    'ine.mx',
    'ipn.mx',
    'tec.mx',
    'uam.mx',
    'imss.gob.mx',
    'condusef.gob.mx',
    'banxico.org.mx',
    'asecoahuila.gob.mx',
    'registry.mx',
    'flacso.edu.mx',
    'sinaloa.gob.mx',
    'tramites.nayarit.gob.mx',
    'hacienda-nayarit.gob.mx',
    'sgg.nayarit.gob.mx',
    'oaxaca.gob.mx',
    'chihuahua.gob.mx',
    'saludsinaloa.gob.mx',
    'elcolegiodesinaloa.gob.mx',
    'cdmx.gob.mx',
    'jalisco.gob.mx',
    'nuestrocine.mx',
    'inba.gob.mx',
    'udem.edu.mx',
    'carteleradeteatro.mx',
    'infonavit.org.mx',
    'cruzrojamexicana.org.mx',
    'hchr.org.mx',
    'amazon.com.mx',
    'mercadolibre.com.mx',
    'sep.gob.mx',
    'walmart.gob.mx',
    'eluniversal.com.mx',
    'tamaulipas.gob.mx',
    'veracruz.gob.mx',
    'morelos.gob.mx',
    'queretaro.gob.mx',
    'zacatecas.gob.mx',
    'pinterest.mx',
    'youtube.mx',
    'christusmuguerza.com.mx',
    'saltillo.tecnm.mx',
    'lasalle.mx',
    'nl.gob.mx',
    'banamex.com.mx',
    'bbva.mx',
    'liverpool.com.mx',
    'bancoazteca.com.mx',
    'bancocomercio.com.mx',
    'issste.gob.mx',
    'cemex.com.mx',
    'femsa.com.mx',
    'alfacorporativo.com.mx',
    'vitro.com.mx',
    'gruma.com.mx',
    'bimbo.com.mx',
    'nemak.com.mx',
    'ternium.com.mx',
    'metalsa.com.mx',
    'deacero.com.mx',
    'chedraui.com.mx',
    'soriana.com.mx',
    'costco.com.mx',
    'homedepot.com.mx',
    'coppel.com.mx',
    'elektra.com.mx',
    'palaciodehierro.com.mx',
    'sanborns.com.mx',
    'santander.com.mx',
    'banorte.com',
    'hsbc.com.mx',
    'scotiabank.com.mx',
    'inbursa.com.mx',
    'banregio.com',
    'afirme.com',
    'banbajio.com',
    'nu.com.mx',
    'klar.mx',
    'izzi.mx',
    'totalplay.com.mx',
    'megacable.com.mx',
    'att.com.mx',
    'movistar.com.mx',
    'ait.com.mx',
    'redcompartida.mx',
    'unicef.org.mx',
    'worldvisionmexico.org.mx',
    'greenpeace.org.mx',
    'caritas.org.mx',
    'amanc.org',
    'fundacionunam.org.mx',
    'savechildren.mx',
    'techo.org.mx',
    'fundacionbbva.mx',
    'proceso.com.mx',
    'expansion.mx',
    'xataka.com.mx'
]

# Algoritmos autorizados según RFC 8624 (estado a 2024)
# (número_algoritmo: (nombre, uso_recomendado))
DNSSEC_ALGORITHMS = {
    1:  ("RSAMD5",           "MUST NOT"),   # RFC 6944 — retirado
    3:  ("DSA",              "MUST NOT"),
    5:  ("RSASHA1",          "NOT RECOMMENDED"),
    6:  ("DSA-NSEC3-SHA1",   "MUST NOT"),
    7:  ("RSASHA1-NSEC3-SHA1","NOT RECOMMENDED"),
    8:  ("RSASHA256",        "MUST"),       # RFC 5702 — recomendado
    10: ("RSASHA512",        "RECOMMENDED"),
    12: ("ECC-GOST",         "MUST NOT"),
    13: ("ECDSAP256SHA256",  "MUST"),       # RFC 6605 — recomendado
    14: ("ECDSAP384SHA384",  "RECOMMENDED"),
    15: ("ED25519",          "RECOMMENDED"), # RFC 8080
    16: ("ED448",            "RECOMMENDED"),
}

# Tipos de clave DNSKEY (flags bit 8 = ZSK, bit 8+256 = KSK/SEP)
DNSKEY_FLAG_ZONE    = 256   # Bit 7 — Zone Key
DNSKEY_FLAG_SEP     = 1     # Bit 15 — Secure Entry Point (KSK)
DNSKEY_FLAG_REVOKED = 128   # Bit 8  — Revocado (RFC 5011)

# Tipos de digest DS
DS_DIGEST_TYPES = {
    1: "SHA-1 (deprecado, RFC 3658)",
    2: "SHA-256 (RFC 4509)",
    3: "GOST R 34.11-94",
    4: "SHA-384 (RFC 6605)",
}

# ─────────────────────────────────────────────────────────────────────────────
# Helpers de consulta DNS
# ─────────────────────────────────────────────────────────────────────────────

def query_rrset(domain: str, rdtype_str: str) -> tuple[Optional[dns.rrset.RRset],
                                                        Optional[dns.rrset.RRset],
                                                        bool]:
    """
    Consulta un RRset con el bit DO activo.
    Devuelve (rrset, rrsig_rrset, ad_flag).
    """
    rdtype = dns.rdatatype.from_text(rdtype_str)
    name   = dns.name.from_text(domain)
    msg    = dns.message.make_query(name, rdtype, want_dnssec=True)
    msg.flags |= dns.flags.CD          # CD=1: no validar en el resolver para obtener datos rotos también

    try:
        resp = dns.query.udp(msg, NAMESERVER, timeout=TIMEOUT)
    except Exception:
        try:
            resp = dns.query.tcp(msg, NAMESERVER, timeout=TIMEOUT)
        except Exception:
            return None, None, False

    ad   = bool(resp.flags & dns.flags.AD)
    data = None
    sig  = None

    for rrset in resp.answer:
        if rrset.rdtype == rdtype and rrset.name == name:
            data = rrset
        if rrset.rdtype == dns.rdatatype.RRSIG and rrset.name == name:
            # Filtra las RRSIG que cubren este tipo
            covers = [r for r in rrset if r.type_covered == rdtype]
            if covers:
                sig = rrset

    # Si no está en answer, buscar en authority (p. ej. NSEC)
    if data is None:
        for rrset in resp.authority:
            if rrset.rdtype == rdtype and rrset.name == name:
                data = rrset
            if rrset.rdtype == dns.rdatatype.RRSIG and rrset.name == name:
                covers = [r for r in rrset if r.type_covered == rdtype]
                if covers:
                    sig = rrset

    return data, sig, ad


# ─────────────────────────────────────────────────────────────────────────────
# Análisis de DNSKEY
# ─────────────────────────────────────────────────────────────────────────────

def analyze_dnskey(domain: str) -> dict:
    result = {"domain": domain, "records": [], "metrics": {}}
    rrset, sig_rrset, _ = query_rrset(domain, "DNSKEY")

    if rrset is None:
        result["metrics"]["found"]      = False
        result["metrics"]["error"]      = "Sin registros DNSKEY"
        return result

    result["metrics"]["found"] = True
    result["metrics"]["ttl"]   = rrset.ttl
    ksk_count = zsk_count = revoked_count = 0
    authorized = deprecated = 0

    for rdata in rrset:
        flags    = rdata.flags
        protocol = rdata.protocol
        algorithm= rdata.algorithm
        key_tag  = dns.dnssec.key_id(rdata)

        is_zone    = bool(flags & DNSKEY_FLAG_ZONE)
        is_sep     = bool(flags & DNSKEY_FLAG_SEP)
        is_revoked = bool(flags & DNSKEY_FLAG_REVOKED)

        if is_sep:   ksk_count += 1
        else:        zsk_count += 1
        if is_revoked: revoked_count += 1

        alg_name, alg_status = DNSSEC_ALGORITHMS.get(algorithm, (f"DESCONOCIDO({algorithm})", "UNKNOWN"))

        if alg_status in ("MUST", "RECOMMENDED"):
            authorized += 1
        else:
            deprecated += 1

        # Estado de la clave
        if is_revoked:
            key_state = "REVOCADA (RFC 5011)"
        elif not is_zone:
            key_state = "INVÁLIDA (Zone Key bit no activo)"
        elif alg_status == "MUST NOT":
            key_state = "INVÁLIDA (algoritmo prohibido)"
        elif alg_status == "NOT RECOMMENDED":
            key_state = "VÁLIDA pero algoritmo no recomendado"
        else:
            key_state = "VÁLIDA"

        rec = {
            "key_tag":   key_tag,
            "type":      "KSK (SEP)" if is_sep else "ZSK",
            "flags":     flags,
            "protocol":  protocol,
            "algorithm": algorithm,
            "alg_name":  alg_name,
            "alg_status": alg_status,
            "key_state": key_state,
            "rfc_compliant": alg_status in ("MUST", "RECOMMENDED") and not is_revoked and is_zone,
        }
        result["records"].append(rec)

    result["metrics"].update({
        "total_keys":   len(rrset),
        "ksk_count":    ksk_count,
        "zsk_count":    zsk_count,
        "revoked":      revoked_count,
        "authorized_alg":  authorized,
        "deprecated_alg":  deprecated,
        "rrsig_present": sig_rrset is not None,
    })
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Análisis de RRSIG
# ─────────────────────────────────────────────────────────────────────────────

def analyze_rrsig(domain: str, rdtype_str: str = "A") -> dict:
    """Analiza el RRSIG que cubre el RRset del tipo indicado."""
    result = {"domain": domain, "rdtype": rdtype_str, "records": [], "metrics": {}}

    # Para la raíz y TLDs usamos SOA, que siempre tiene firma
    if domain in (".", "com.", "net.", "org."):
        rdtype_str = "SOA"
        result["rdtype"] = "SOA"

    _, sig_rrset, ad = query_rrset(domain, rdtype_str)

    # Fallback: intentar con SOA si A no tiene RRSIG
    if sig_rrset is None and rdtype_str == "A":
        _, sig_rrset, ad = query_rrset(domain, "SOA")
        if sig_rrset is not None:
            result["rdtype"] = "SOA"

    result["metrics"]["ad_flag"] = ad

    if sig_rrset is None:
        result["metrics"]["found"] = False
        result["metrics"]["error"] = "Sin RRSIG"
        return result

    result["metrics"]["found"] = True
    result["metrics"]["ttl"]   = sig_rrset.ttl
    now = datetime.now(timezone.utc)
    valid_count = expired_count = future_count = 0

    for rdata in sig_rrset:
        type_covered = dns.rdatatype.to_text(rdata.type_covered)
        inception    = rdata.inception
        expiration   = rdata.expiration
        # Convertir a datetime con timezone
        inception_dt  = datetime.fromtimestamp(inception,  tz=timezone.utc)
        expiration_dt = datetime.fromtimestamp(expiration, tz=timezone.utc)

        if now < inception_dt:
            state = "NO VÁLIDA AÚN (futura)"
            future_count += 1
        elif now > expiration_dt:
            state = "EXPIRADA"
            expired_count += 1
        else:
            state = "VÁLIDA"
            valid_count += 1

        alg_name, _ = DNSSEC_ALGORITHMS.get(rdata.algorithm, (f"ALG-{rdata.algorithm}", "?"))

        rec = {
            "type_covered": type_covered,
            "algorithm":    rdata.algorithm,
            "alg_name":     alg_name,
            "key_tag":      rdata.key_tag,
            "signer":       str(rdata.signer),
            "inception":    inception_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "expiration":   expiration_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "labels":       rdata.labels,
            "original_ttl": rdata.original_ttl,
            "state":        state,
        }
        result["records"].append(rec)

    result["metrics"].update({
        "total":   len(result["records"]),
        "valid":   valid_count,
        "expired": expired_count,
        "future":  future_count,
    })
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Análisis de NSEC / NSEC3 / NSEC3PARAM
# ─────────────────────────────────────────────────────────────────────────────

def analyze_nsec(domain: str) -> dict:
    result = {"domain": domain, "type": None, "records": [], "metrics": {}}

    # Intentar NSEC3PARAM primero (implica uso de NSEC3)
    nsec3param, _, _ = query_rrset(domain, "NSEC3PARAM")
    nsec3,       _, _ = query_rrset(domain, "NSEC3")
    nsec,        _, _ = query_rrset(domain, "NSEC")

    if nsec3param is not None:
        result["type"] = "NSEC3PARAM+NSEC3"
        result["metrics"]["ttl"] = nsec3param.ttl
        for rdata in nsec3param:
            result["records"].append({
                "record_type": "NSEC3PARAM",
                "hash_algorithm": rdata.algorithm,
                "hash_alg_name":  "SHA-1" if rdata.algorithm == 1 else f"ALG-{rdata.algorithm}",
                "flags":     rdata.flags,
                "iterations": rdata.iterations,
                "salt":      rdata.salt.hex() if rdata.salt else "(vacío)",
                "rfc_note":  "RFC 5155 — iteraciones >0 aumentan coste de enumeración",
                "rfc_compliant": rdata.iterations <= 100,
            })
    elif nsec3 is not None:
        result["type"] = "NSEC3"
        result["metrics"]["ttl"] = nsec3.ttl
        for rdata in nsec3:
            result["records"].append({
                "record_type": "NSEC3",
                "hash_algorithm": rdata.algorithm,
                "flags":      rdata.flags,
                "iterations": rdata.iterations,
                "salt":       rdata.salt.hex() if rdata.salt else "(vacío)",
            })
    elif nsec is not None:
        result["type"] = "NSEC"
        result["metrics"]["ttl"] = nsec.ttl
        for rdata in nsec:
            result["records"].append({
                "record_type": "NSEC",
                "next_name":   str(rdata.next),
                "windows":     str(rdata.windows),
                "rfc_note":    "RFC 4034 — expone estructura de zona (enumeración posible)",
            })
    else:
        result["type"] = "NINGUNO"
        result["metrics"]["found"] = False
        result["metrics"]["error"] = "Sin NSEC/NSEC3/NSEC3PARAM (dominio sin DNSSEC o zona vacía)"

    result["metrics"]["found"]       = result["type"] != "NINGUNO"
    result["metrics"]["uses_nsec3"]  = "NSEC3" in (result["type"] or "")
    result["metrics"]["uses_nsec"]   = result["type"] == "NSEC"
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Análisis de DS y cadena de confianza
# ─────────────────────────────────────────────────────────────────────────────

def compute_ds(dnskey_rdata, owner_name: str, digest_type: int = 2) -> str:
    """Calcula el DS esperado para un DNSKEY dado (RFC 4034 §5.1.4)."""
    name_wire = dns.name.from_text(owner_name).canonicalize().to_wire()
    # Wire-format del DNSKEY: flags(2) + protocol(1) + algorithm(1) + public_key
    key_wire  = struct.pack("!HBB", dnskey_rdata.flags,
                            dnskey_rdata.protocol,
                            dnskey_rdata.algorithm) + dnskey_rdata.key
    data = name_wire + key_wire
    if digest_type == 1:
        return hashlib.sha1(data).hexdigest().upper()
    elif digest_type == 2:
        return hashlib.sha256(data).hexdigest().upper()
    elif digest_type == 4:
        return hashlib.sha384(data).hexdigest().upper()
    return ""


def analyze_ds(domain: str) -> dict:
    result = {"domain": domain, "records": [], "metrics": {}}
    ds_rrset, sig_rrset, _ = query_rrset(domain, "DS")

    if ds_rrset is None:
        result["metrics"]["found"] = False
        result["metrics"]["error"] = "Sin registros DS (dominio raíz o sin DNSSEC delegado)"
        return result

    result["metrics"]["found"] = True
    result["metrics"]["ttl"]   = ds_rrset.ttl
    result["metrics"]["rrsig_covers_ds"] = sig_rrset is not None

    # Obtener DNSKEY del hijo para verificar
    dnskey_rrset, _, _ = query_rrset(domain, "DNSKEY")
    valid_chain = 0
    broken_chain = 0

    for rdata in ds_rrset:
        digest_name = DS_DIGEST_TYPES.get(rdata.digest_type, f"TIPO-{rdata.digest_type}")
        deprecated  = rdata.digest_type == 1    # SHA-1 deprecado
        alg_name, _ = DNSSEC_ALGORITHMS.get(rdata.algorithm, (f"ALG-{rdata.algorithm}", "?"))

        chain_ok    = False
        computed_ds = ""

        if dnskey_rrset is not None:
            # Buscar la DNSKEY con el key_tag correspondiente
            for dnskey in dnskey_rrset:
                if dns.dnssec.key_id(dnskey) == rdata.key_tag:
                    computed_ds = compute_ds(dnskey, domain, rdata.digest_type)
                    stored_ds   = rdata.digest.hex().upper()
                    chain_ok    = (computed_ds == stored_ds)
                    break

        if chain_ok:
            valid_chain += 1
        else:
            broken_chain += 1

        rec = {
            "key_tag":     rdata.key_tag,
            "algorithm":   rdata.algorithm,
            "alg_name":    alg_name,
            "digest_type": rdata.digest_type,
            "digest_name": digest_name,
            "digest":      rdata.digest.hex().upper(),
            "computed_ds": computed_ds,
            "chain_valid": chain_ok,
            "digest_deprecated": deprecated,
            "rfc_note":    "RFC 4034 §5 — SHA-1 (tipo 1) obsoleto según RFC 8624" if deprecated else "",
        }
        result["records"].append(rec)

    result["metrics"].update({
        "total":         len(ds_rrset),
        "chain_valid":   valid_chain,
        "chain_broken":  broken_chain,
        "trust_chain_ok": broken_chain == 0 and valid_chain > 0,
    })
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Árbol DNS y cadena de confianza
# ─────────────────────────────────────────────────────────────────────────────

def build_trust_tree(domains: list[str]) -> dict:
    """
    Construye el árbol de dependencias DNS desde la raíz hasta cada dominio.
    Verifica la cadena DS→DNSKEY en cada eslabón.
    """
    # Recolectar todos los nodos únicos (raíz + TLDs + dominios)
    nodes = set()
    nodes.add(".")
    for d in domains:
        parts = d.rstrip(".").split(".")
        for i in range(len(parts)):
            sub = ".".join(parts[i:]) + "."
            nodes.add(sub)
        nodes.add(d if d.endswith(".") else d + ".")

    tree  = {}
    edges = []  # (padre, hijo, ds_valid)

    for node in sorted(nodes, key=lambda x: len(x)):
        if node == ".":
            parent = None
        else:
            # Obtener padre
            parts  = node.rstrip(".").split(".")
            parent = (".".join(parts[1:]) + ".") if len(parts) > 1 else "."

        ds_result   = analyze_ds(node) if node != "." else {"metrics": {"found": False}}
        dnskey_result = analyze_dnskey(node)

        tree[node] = {
            "parent":       parent,
            "has_dnskey":   dnskey_result["metrics"].get("found", False),
            "has_ds":       ds_result["metrics"].get("found", False),
            "trust_chain":  ds_result["metrics"].get("trust_chain_ok", False),
            "ds_ttl":       ds_result["metrics"].get("ttl", None),
            "dnskey_ttl":   dnskey_result["metrics"].get("ttl", None),
            "ksk_count":    dnskey_result["metrics"].get("ksk_count", 0),
            "zsk_count":    dnskey_result["metrics"].get("zsk_count", 0),
        }

        if parent is not None:
            chain_ok = ds_result["metrics"].get("trust_chain_ok", False)
            edges.append((parent, node, chain_ok))

    return {"nodes": tree, "edges": edges}


# ─────────────────────────────────────────────────────────────────────────────
# Reporte ASCII
# ─────────────────────────────────────────────────────────────────────────────

def print_section(title: str):
    print("\n" + "═" * 72)
    print(f"  {title}")
    print("═" * 72)

def print_subsection(title: str):
    print(f"\n  ── {title} ──")

def fmt_bool(v: bool) -> str:
    return "✓ SÍ" if v else "✗ NO"

def run_analysis():
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║         ANALIZADOR DNSSEC — MA2002B  Tec de Monterrey               ║")
    print("║         RFC 4033/4034/4035/5155/6840/8624                           ║")
    print(f"║         Fecha: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'):<54}║")
    print("╚══════════════════════════════════════════════════════════════════════╝")

    all_results = {}

    # ── DNSKEY ────────────────────────────────────────────────────────────────
    print_section("1. REGISTROS DNSKEY")
    dnskey_results = {}
    for domain in DOMAINS:
        res = analyze_dnskey(domain)
        dnskey_results[domain] = res
        m   = res["metrics"]
        print(f"\n  Dominio: {domain}")
        if not m.get("found"):
            print(f"    → Sin DNSKEY ({m.get('error','')})")
            continue
        print(f"    TTL            : {m['ttl']} s")
        print(f"    Total claves   : {m['total_keys']}  (KSK={m['ksk_count']}, ZSK={m['zsk_count']})")
        print(f"    Alg. autorizados: {m['authorized_alg']}  |  Deprecados: {m['deprecated_alg']}")
        print(f"    Revocadas      : {m['revoked']}")
        for r in res["records"]:
            print(f"      KeyTag={r['key_tag']:5d}  Tipo={r['type']:<10}  "
                  f"Alg={r['alg_name']:<22} [{r['alg_status']}]  → {r['key_state']}")

    # ── RRSIG ────────────────────────────────────────────────────────────────
    print_section("2. REGISTROS RRSIG")
    rrsig_results = {}
    for domain in DOMAINS:
        res = analyze_rrsig(domain)
        rrsig_results[domain] = res
        m   = res["metrics"]
        print(f"\n  Dominio: {domain}  (tipo consultado: {res['rdtype']})")
        if not m.get("found"):
            print(f"    → Sin RRSIG ({m.get('error','')})")
            continue
        print(f"    TTL     : {m['ttl']} s    |   AD flag: {fmt_bool(m['ad_flag'])}")
        print(f"    Firmas  : {m['total']}  válidas={m['valid']}  expiradas={m['expired']}  futuras={m['future']}")
        for r in res["records"]:
            print(f"      KeyTag={r['key_tag']:5d}  Alg={r['alg_name']:<22}  "
                  f"Firmante={r['signer']}")
            print(f"        Inicio     : {r['inception']}")
            print(f"        Expiración : {r['expiration']}")
            print(f"        Estado     : {r['state']}")

    # ── NSEC/NSEC3 ────────────────────────────────────────────────────────────
    print_section("3. REGISTROS NSEC / NSEC3 / NSEC3PARAM")
    nsec_results = {}
    for domain in DOMAINS:
        if domain in (".", "com."):   # skip raíz/TLD (no tienen NSEC en consulta directa)
            continue
        res = analyze_nsec(domain)
        nsec_results[domain] = res
        m   = res["metrics"]
        print(f"\n  Dominio: {domain}")
        print(f"    Tipo detectado : {res['type']}")
        if not m.get("found"):
            print(f"    → {m.get('error','')}")
            continue
        print(f"    TTL            : {m.get('ttl','N/A')} s")
        print(f"    Usa NSEC3      : {fmt_bool(m['uses_nsec3'])}")
        print(f"    Usa NSEC       : {fmt_bool(m['uses_nsec'])}")
        for r in res["records"]:
            if r["record_type"] == "NSEC3PARAM":
                print(f"    NSEC3PARAM  Alg={r['hash_alg_name']}  "
                      f"Iter={r['iterations']}  Salt={r['salt']}")
                print(f"      RFC 5155: iter<=100 → {fmt_bool(r['rfc_compliant'])}")
            elif r["record_type"] == "NSEC":
                print(f"    NSEC  Siguiente={r['next_name']}")
                print(f"      {r['rfc_note']}")

    # ── DS ───────────────────────────────────────────────────────────────────
    print_section("4. REGISTROS DS — CADENA DE CONFIANZA")
    ds_results = {}
    for domain in DOMAINS:
        if domain == ".":
            continue
        res = analyze_ds(domain)
        ds_results[domain] = res
        m   = res["metrics"]
        print(f"\n  Dominio: {domain}")
        if not m.get("found"):
            print(f"    → Sin DS ({m.get('error','')})")
            continue
        print(f"    TTL             : {m['ttl']} s")
        print(f"    RRSIG cubre DS  : {fmt_bool(m['rrsig_covers_ds'])}")
        print(f"    Cadena íntegra  : {fmt_bool(m['trust_chain_ok'])}")
        for r in res["records"]:
            estado = "✓ VÁLIDA" if r["chain_valid"] else "✗ ROTA/NO VERIFICABLE"
            print(f"      KeyTag={r['key_tag']:5d}  Alg={r['alg_name']:<22}  "
                  f"Digest={r['digest_name']:<20}  Cadena={estado}")
            if r["digest_deprecated"]:
                print(f"        ⚠ {r['rfc_note']}")

    # ── ÁRBOL DNS ────────────────────────────────────────────────────────────
    print_section("5. ÁRBOL DNS — CADENA DE CONFIANZA (raíz → dominios)")
    print("\n  Consultando árbol... (puede tardar unos segundos)\n")
    # Usar subconjunto de 5-7 dominios para el árbol
    tree_domains = [d for d in DOMAINS if d not in (".", "com.")][:7]
    tree = build_trust_tree(tree_domains)

    # Imprimir árbol ASCII
    def print_tree(node, tree_nodes, edges, prefix="", is_last=True):
        n = tree_nodes.get(node, {})
        connector = "└── " if is_last else "├── "
        dnssec_ok = n.get("has_dnskey") and n.get("has_ds") and n.get("trust_chain")
        has_dnskey = n.get("has_dnskey", False)

        if node == ".":
            tag = "[RAÍZ — Ancla de confianza RFC 4033]"
        elif dnssec_ok:
            tag = "[DNSSEC OK ✓]"
        elif has_dnskey and not n.get("has_ds"):
            tag = "[DNSKEY sin DS — cadena incompleta ⚠]"
        elif has_dnskey:
            tag = "[DNSKEY+DS — verificar cadena ⚠]"
        else:
            tag = "[Sin DNSSEC ✗]"

        ttl_info = ""
        if n.get("dnskey_ttl"):
            ttl_info = f"  TTL-DNSKEY={n['dnskey_ttl']}s"
        if n.get("ds_ttl"):
            ttl_info += f"  TTL-DS={n['ds_ttl']}s"

        if node == ".":
            print(f"  {node} {tag}")
        else:
            print(f"  {prefix}{connector}{node} {tag}{ttl_info}")

        children = [e[1] for e in edges if e[0] == node]
        for i, child in enumerate(sorted(children)):
            is_last_child = (i == len(children) - 1)
            new_prefix = prefix + ("    " if is_last else "│   ")
            print_tree(child, tree_nodes, edges, new_prefix, is_last_child)

    print_tree(".", tree["nodes"], tree["edges"])

    # Resumen de cadena de confianza
    print_subsection("Resumen cadena de confianza")
    for parent, child, chain_ok in sorted(tree["edges"]):
        estado = "✓ íntegra" if chain_ok else "✗ rota o no verificable"
        print(f"    {parent:30s} → {child:35s} DS: {estado}")

    # ── MÉTRICAS GLOBALES ────────────────────────────────────────────────────
    print_section("6. MÉTRICAS GLOBALES")

    total = len(DOMAINS)
    has_dnskey     = sum(1 for d in DOMAINS if dnskey_results.get(d, {}).get("metrics", {}).get("found", False))
    has_rrsig      = sum(1 for d in DOMAINS if rrsig_results.get(d,  {}).get("metrics", {}).get("found", False))
    has_ds_valid   = sum(1 for d in DOMAINS if ds_results.get(d,     {}).get("metrics", {}).get("trust_chain_ok", False))
    has_nsec3      = sum(1 for d in nsec_results if nsec_results[d]["metrics"].get("uses_nsec3", False))
    has_nsec_only  = sum(1 for d in nsec_results if nsec_results[d]["metrics"].get("uses_nsec",  False))
    rrsig_expired  = sum(1 for d in DOMAINS if rrsig_results.get(d, {}).get("metrics", {}).get("expired", 0) > 0)
    alg_authorized = sum(
        dnskey_results[d]["metrics"].get("authorized_alg", 0)
        for d in DOMAINS if dnskey_results.get(d, {}).get("metrics", {}).get("found", False)
    )
    alg_deprecated = sum(
        dnskey_results[d]["metrics"].get("deprecated_alg", 0)
        for d in DOMAINS if dnskey_results.get(d, {}).get("metrics", {}).get("found", False)
    )

    print(f"\n  Dominios analizados         : {total}")
    print(f"  Con DNSKEY                  : {has_dnskey}/{total}  ({100*has_dnskey//total}%)")
    print(f"  Con RRSIG válido            : {has_rrsig}/{total}  ({100*has_rrsig//total}%)")
    print(f"  Con cadena DS íntegra       : {has_ds_valid}/{total-1}")   # raíz no tiene DS padre
    print(f"  Usan NSEC3 (más seguro)     : {has_nsec3}")
    print(f"  Usan NSEC  (enumeración)    : {has_nsec_only}")
    print(f"  Firmas RRSIG expiradas      : {rrsig_expired} dominios")
    print(f"  Algoritmos autorizados (RFC 8624): {alg_authorized}")
    print(f"  Algoritmos deprecados/prohibidos : {alg_deprecated}")

    print("\n  Leyenda de cumplimiento RFC:")
    print("    RFC 4033/4034/4035 — Protocolo DNSSEC base")
    print("    RFC 5155           — NSEC3 (protección contra enumeración de zona)")
    print("    RFC 6840           — Aclaraciones DNSSEC")
    print("    RFC 8624           — Recomendaciones de algoritmos (2019)")
    print("    RFC 4509/6605      — DS SHA-256 y ECDSA")

    print("\n" + "═" * 72)
    print("  Análisis completado.")
    print("═" * 72 + "\n")

    # ── Guardar JSON ─────────────────────────────────────────────────────────
    output = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nameserver": NAMESERVER,
        "domains": DOMAINS,
        "dnskey":  {k: v for k, v in dnskey_results.items()},
        "rrsig":   {k: v for k, v in rrsig_results.items()},
        "nsec":    nsec_results,
        "ds":      ds_results,
        "trust_tree": {
            "nodes": tree["nodes"],
            "edges": [{"parent": e[0], "child": e[1], "chain_ok": e[2]}
                      for e in tree["edges"]],
        },
        "global_metrics": {
            "total_domains":      total,
            "with_dnskey":        has_dnskey,
            "with_rrsig":         has_rrsig,
            "ds_chain_valid":     has_ds_valid,
            "use_nsec3":          has_nsec3,
            "use_nsec_only":      has_nsec_only,
            "rrsig_expired":      rrsig_expired,
            "alg_authorized":     alg_authorized,
            "alg_deprecated":     alg_deprecated,
        },
    }

    with open("dnssec_results.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)

    print("  Resultados guardados en: dnssec_results.json\n")


if __name__ == "__main__":
    run_analysis()