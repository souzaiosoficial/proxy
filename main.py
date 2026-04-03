import os
import json
import threading
import time
from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify
from datetime import datetime, timedelta
import asyncio
from mitmproxy import http
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options

# --- CONFIGURAÇÕES DO PAINEL WEB ---
app = Flask(__name__ )
app.secret_key = "senha_admin_railway_final"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LICENSES_FILE = os.path.join(BASE_DIR, "licencas.json")

def load_licenses():
    if os.path.exists(LICENSES_FILE):
        try:
            with open(LICENSES_FILE, "r") as f: return json.load(f)
        except: return {}
    return {}

def save_licenses(licenses):
    with open(LICENSES_FILE, "w") as f: json.dump(licenses, f, indent=4)

ADMIN_HTML = """
<html><body style='font-family:sans-serif;padding:20px;background:#f0f2f5;'>
    <div style='max-width:800px;margin:auto;background:white;padding:30px;border-radius:15px;box-shadow:0 4px 15px rgba(0,0,0,0.1);'>
    <h1 style='color:#1a73e8;'>Painel Proxy UDID - RAILWAY</h1>
    <form action='/add' method='post'>
        UDID: <input name='udid' required style='padding:10px;'>
        Tempo: <select name='dias'><option value='7'>7 dias</option><option value='30'>30 dias</option></select>
        <button type='submit' style='padding:10px;background:#28a745;color:white;border:none;border-radius:5px;cursor:pointer;'>LIBERAR</button>
    </form>
    <table border='0' style='width:100%;border-collapse:collapse;margin-top:20px;'>
        <tr style='background:#1a73e8;color:white;'><th>UDID</th><th>Expiração</th><th>Status</th><th>Ação</th></tr>
        {% for udid, exp_date in licenses.items() %}
        <tr style='border-bottom:1px solid #eee;'>
            <td style='padding:12px;'>{{ udid }}</td><td style='padding:12px;'>{{ exp_date }}</td>
            <td style='padding:12px;'>{{ "Ativo" if exp_date > now else "Expirado" }}</td>
            <td style='padding:12px;'><a href='/del/{{ udid }}' style='color:#d93025;'>Excluir</a></td>
        </tr>
        {% endfor %}
    </table>
    </div>
</body></html>
"""

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get('logged_in'):
        if request.method == 'POST' and request.form['password'] == 'admin123':
            session['logged_in'] = True
            return redirect(url_for('admin'))
        return "<html><body style='text-align:center;padding-top:100px;'><h1>Admin</h1><form method='post'>Senha: <input type='password' name='password'><input type='submit'></form></body></html>"
    licenses = load_licenses()
    return render_template_string(ADMIN_HTML, licenses=licenses, now=datetime.now().strftime("%Y-%m-%d"))

@app.route('/add', methods=['POST'])
def add():
    if not session.get('logged_in'): return redirect(url_for('admin'))
    udid, dias = request.form['udid'].strip(), int(request.form['dias'])
    licenses = load_licenses()
    licenses[udid] = (datetime.now() + timedelta(days=dias)).strftime("%Y-%m-%d")
    save_licenses(licenses)
    return redirect(url_for('admin'))

@app.route('/del/<udid>')
def delete(udid):
    if not session.get('logged_in'): return redirect(url_for('admin'))
    licenses = load_licenses()
    if udid in licenses: del licenses[udid]; save_licenses(licenses)
    return redirect(url_for('admin'))

# --- LÓGICA DO PROXY ---
def load_asset(filename):
    path = os.path.join(BASE_DIR, filename)
    if os.path.exists(path):
        h = open(path, "r").read().strip().replace(" ", "").replace("\n", "").replace("\r", "")
        b = bytearray()
        for i in range(0, len(h), 2): b.append(int(h[i:i+2], 16))
        return bytes(b)
    return None

indr_bytes = load_asset("indr.txt")
_3dr_bytes = load_asset("3dr.txt")
AUTHORIZED_IPS = {}

class ProxyAddon:
    def request(self, flow: http.HTTPFlow ):
        url, ip = flow.request.pretty_url, flow.client_conn.peername[0]
        
        # Ativação UDID
        if "proxy.local/ativar" in url:
            udid = flow.request.query.get("udid")
            if udid in load_licenses():
                AUTHORIZED_IPS[ip] = udid
                flow.response = http.Response.make(200, b"Ativado com Sucesso!", {"Content-Type": "text/plain"} )
            else:
                flow.response = http.Response.make(403, b"UDID nao autorizado.", {"Content-Type": "text/plain"} )
            return

        # Bloqueio de segurança
        if ip not in AUTHORIZED_IPS and any(d in url for d in ["freefire", "garena", "GetBackpack", "fileinfo", "assetindexer"]):
            flow.response = http.Response.make(403, b"Aparelho nao autorizado. Ative seu UDID.", {"Content-Type": "text/plain"} )

    def response(self, flow: http.HTTPFlow ):
        url, ip = flow.request.pretty_url, flow.client_conn.peername[0]
        if ip not in AUTHORIZED_IPS: return

        if "/CheckHackBehavior" in url or "/GetMatchmakingBlacklist" in url:
            flow.response = http.Response.make(403, b"Loi", {"Content-Type": "text/plain"} )
        elif "/GetBackpack" in url and flow.request.method == "POST":
            flow.response = http.Response.make(200, b"", {"Content-Type": "application/json"} )
        elif "/fileinfo" in url and indr_bytes:
            flow.response = http.Response.make(200, indr_bytes, {"Content-Type": "application/octet-stream"} )
        elif "/assetindexer" in url and _3dr_bytes:
            flow.response = http.Response.make(200, _3dr_bytes, {"Content-Type": "application/octet-stream"} )

async def start_proxy():
    port = int(os.environ.get("PORT", 8080))
    opts = Options(listen_host='0.0.0.0', listen_port=port, confdir="/tmp/.mitmproxy")
    m = DumpMaster(opts)
    m.addons.add(ProxyAddon())
    await m.run()

if __name__ == '__main__':
    # Roda o Flask na porta 5000 interna
    threading.Thread(target=lambda: app.run(host='127.0.0.1', port=5000), daemon=True).start()
    # Roda o Proxy na porta principal do Railway
    asyncio.run(start_proxy())
