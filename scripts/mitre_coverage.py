#!/usr/bin/env python3
"""
Consulta o Wazuh Indexer para gerar um relatorio de cobertura MITRE ATT&CK,
com base nos alertas reais gerados pelo servidor (nao simulados).

Requer as variaveis de ambiente:
  WAZUH_INDEXER_PASS
"""

import os
import sys
import json
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INDEXER_URL = "https://192.168.1.90:9200"
USER = os.environ.get("WAZUH_INDEXER_USER", "admin")
PASSWORD = os.environ.get("WAZUH_INDEXER_PASS")

if not PASSWORD:
    print("ERRO: defina WAZUH_INDEXER_PASS como variavel de ambiente antes de correr.")
    sys.exit(1)


def get_technique_counts():
    body = {
        "size": 0,
        "query": {"exists": {"field": "rule.mitre"}},
        "aggs": {
            "tecnicas": {"terms": {"field": "rule.mitre.technique", "size": 50}}
        },
    }
    resp = requests.post(
        f"{INDEXER_URL}/wazuh-alerts-*/_search",
        auth=(USER, PASSWORD),
        headers={"Content-Type": "application/json"},
        json=body,
        verify=False,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("aggregations", {}).get("tecnicas", {}).get("buckets", [])


def get_tactic_counts():
    body = {
        "size": 0,
        "query": {"exists": {"field": "rule.mitre"}},
        "aggs": {
            "taticas": {"terms": {"field": "rule.mitre.tactic", "size": 50}}
        },
    }
    resp = requests.post(
        f"{INDEXER_URL}/wazuh-alerts-*/_search",
        auth=(USER, PASSWORD),
        headers={"Content-Type": "application/json"},
        json=body,
        verify=False,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("aggregations", {}).get("taticas", {}).get("buckets", [])


def get_top_source_ips(limit=10):
    body = {
        "size": 0,
        "query": {"match": {"rule.mitre.technique": "Password Guessing"}},
        "aggs": {
            "top_ips": {"terms": {"field": "data.srcip", "size": limit}}
        },
    }
    resp = requests.post(
        f"{INDEXER_URL}/wazuh-alerts-*/_search",
        auth=(USER, PASSWORD),
        headers={"Content-Type": "application/json"},
        json=body,
        verify=False,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("aggregations", {}).get("top_ips", {}).get("buckets", [])


if __name__ == "__main__":
    print("A gerar relatorio de cobertura MITRE ATT&CK...\n")

    tecnicas = get_technique_counts()
    taticas = get_tactic_counts()
    top_ips = get_top_source_ips()

    print(f"=== Taticas MITRE cobertas: {len(taticas)} ===")
    for t in taticas:
        print(f"  {t['key']}: {t['doc_count']} alertas")

    print(f"\n=== Tecnicas MITRE detectadas: {len(tecnicas)} ===")
    for t in tecnicas:
        print(f"  {t['key']}: {t['doc_count']} alertas")

    print(f"\n=== Top {len(top_ips)} IPs de origem em tentativas de password guessing ===")
    for ip in top_ips:
        print(f"  {ip['key']}: {ip['doc_count']} tentativas")

    output = {
        "taticas": {t["key"]: t["doc_count"] for t in taticas},
        "tecnicas": {t["key"]: t["doc_count"] for t in tecnicas},
        "top_ips_brute_force": {ip["key"]: ip["doc_count"] for ip in top_ips},
    }
    with open("mitre_coverage_report.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print("\nRelatorio guardado em mitre_coverage_report.json")
