#!/usr/bin/env python3
"""
CyberArk Privilege Cloud - Monitor de Licenças
Verifica o consumo de licenças e envia alerta no Microsoft Teams quando
o uso ultrapassar o threshold configurado.

Uso:
    python cyberark_license_monitor.py

Variáveis de ambiente necessárias:
    CYBERARK_TENANT        - Subdomínio do tenant (ex: agiplan)
    CYBERARK_CLIENT_ID     - Username do service user OAuth
    CYBERARK_CLIENT_SECRET - Senha do service user
    TEAMS_WEBHOOK_URL      - Webhook do canal do Teams para alertas
    LICENSE_THRESHOLD      - Percentual para disparar alerta (padrão: 80)
"""

import os
import sys
import json
import requests
from datetime import datetime

# ---------------------------------------------------------------------------
# Configuração via variáveis de ambiente
# ---------------------------------------------------------------------------
TENANT = os.environ.get("CYBERARK_TENANT", "agiplan")
CLIENT_ID = os.environ.get("CYBERARK_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("CYBERARK_CLIENT_SECRET", "")
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "")
THRESHOLD = int(os.environ.get("LICENSE_THRESHOLD", "80"))

IDENTITY_URL = f"https://{TENANT}.id.cyberark.cloud"
PCLOUD_URL = f"https://{TENANT}.privilegecloud.cyberark.cloud"


def get_token() -> str:
    """Obtém token OAuth2 via client_credentials."""
    url = f"{IDENTITY_URL}/oauth2/platformtoken"
    response = requests.post(
        url,
        data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def get_licenses(token: str) -> dict:
    """Consulta o relatório de licenças do Privilege Cloud."""
    url = f"{PCLOUD_URL}/PasswordVault/API/licenses/pcloud/"
    response = requests.get(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def parse_licenses(data: dict) -> list[dict]:
    """Extrai e calcula percentual de uso por tipo de licença."""
    results = []
    summary = data.get("optionalSummary", {})
    if summary:
        used = int(summary.get("used", 0))
        total = int(summary.get("total", 1))
        results.append({
            "name": "TOTAL",
            "used": used,
            "total": total,
            "percent": round(used / total * 100, 1) if total > 0 else 0,
        })

    for block in data.get("licensesData", []):
        for item in block.get("licencesElements", []):
            used = int(item.get("used", 0))
            total = int(item.get("total", 1))
            results.append({
                "name": item["name"],
                "used": used,
                "total": total,
                "percent": round(used / total * 100, 1) if total > 0 else 0,
            })
    return results


def build_teams_message(licenses: list[dict], alerts: list[dict]) -> dict:
    """Monta o payload Adaptive Card para o Teams."""
    now = datetime.now().strftime("%d/%m/%Y %H:%M")
    has_alert = bool(alerts)

    color = "attention" if has_alert else "good"
    title = (
        f"ALERTA: Licenças CyberArk acima de {THRESHOLD}%"
        if has_alert
        else "CyberArk - Consumo de Licenças OK"
    )

    rows = []
    for lic in licenses:
        bar = "█" * int(lic["percent"] / 10) + "░" * (10 - int(lic["percent"] / 10))
        flag = " ⚠️" if lic["percent"] >= THRESHOLD else ""
        rows.append({
            "type": "TableRow",
            "cells": [
                {"type": "TableCell", "items": [{"type": "TextBlock", "text": lic["name"] + flag, "wrap": True}]},
                {"type": "TableCell", "items": [{"type": "TextBlock", "text": f"{lic['used']}/{lic['total']}", "wrap": True}]},
                {"type": "TableCell", "items": [{"type": "TextBlock", "text": f"{bar} {lic['percent']}%", "wrap": True, "fontType": "Monospace"}]},
            ],
        })

    card = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": title,
                            "size": "Large",
                            "weight": "Bolder",
                            "color": color,
                            "wrap": True,
                        },
                        {
                            "type": "TextBlock",
                            "text": f"Tenant: **{TENANT}** | Threshold: **{THRESHOLD}%** | {now}",
                            "isSubtle": True,
                            "wrap": True,
                        },
                        {
                            "type": "Table",
                            "columns": [
                                {"width": 3},
                                {"width": 1},
                                {"width": 3},
                            ],
                            "rows": [
                                {
                                    "type": "TableRow",
                                    "style": "accent",
                                    "cells": [
                                        {"type": "TableCell", "items": [{"type": "TextBlock", "text": "Tipo de Licença", "weight": "Bolder"}]},
                                        {"type": "TableCell", "items": [{"type": "TextBlock", "text": "Uso", "weight": "Bolder"}]},
                                        {"type": "TableCell", "items": [{"type": "TextBlock", "text": "Percentual", "weight": "Bolder"}]},
                                    ],
                                },
                                *rows,
                            ],
                        },
                    ],
                },
            }
        ],
    }
    return card


def send_teams_alert(payload: dict) -> None:
    """Envia mensagem para o webhook do Teams."""
    response = requests.post(
        TEAMS_WEBHOOK_URL,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=15,
    )
    response.raise_for_status()


def main() -> int:
    # Validação de configuração
    missing = [v for v in ["CYBERARK_CLIENT_ID", "CYBERARK_CLIENT_SECRET", "TEAMS_WEBHOOK_URL"] if not os.environ.get(v)]
    if missing:
        print(f"[ERRO] Variáveis de ambiente não configuradas: {', '.join(missing)}")
        print("Configure as variáveis e tente novamente. Veja o --help no topo do arquivo.")
        return 1

    print(f"[{datetime.now():%H:%M:%S}] Buscando token...")
    token = get_token()

    print(f"[{datetime.now():%H:%M:%S}] Consultando licenças...")
    data = get_licenses(token)

    licenses = parse_licenses(data)
    alerts = [lic for lic in licenses if lic["percent"] >= THRESHOLD]

    print(f"\n{'Tipo':<40} {'Usado':>6} {'Total':>6} {'%':>6}")
    print("-" * 62)
    for lic in licenses:
        flag = " <<< ALERTA" if lic["percent"] >= THRESHOLD else ""
        print(f"{lic['name']:<40} {lic['used']:>6} {lic['total']:>6} {lic['percent']:>5}%{flag}")

    if alerts:
        print(f"\n[ALERTA] {len(alerts)} tipo(s) acima de {THRESHOLD}%")
    else:
        print(f"\n[OK] Todas as licenças abaixo de {THRESHOLD}%")

    print(f"\n[{datetime.now():%H:%M:%S}] Enviando para o Teams...")
    payload = build_teams_message(licenses, alerts)
    send_teams_alert(payload)
    print("[OK] Mensagem enviada!")

    return 0


if __name__ == "__main__":
    sys.exit(main())
