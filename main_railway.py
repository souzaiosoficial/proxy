import os
import json
import threading
import time
from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify
from datetime import datetime, timedelta
from mitmproxy import http
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options

# --- CONFIGURAÇÕES DO PAINEL WEB ---
app = Flask(__name__)
app.secret_key = "senha_admin_railway" # Mude para sua seguranca

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LICENSES_FILE = os.path.join(BASE_DIR, "licencas.json")

def load_licenses():
    if os.path.exists(LICENSES_FILE):
        try:
            with open(LICENSES_FILE, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_licenses(licenses):
    with open(LICENSES_FILE, "w") as f:
        json.dump(licenses, f, indent=4)

ADMIN_HTML = """
<html><body style='font-family:sans-serif;padding:20px;background:#f0f2f5;'>
    <div style='max-width:800px;margin:auto;background:white;padding:30px;border-radius:15px;box-shadow:0 4px 15px rgba(0,0,0,0.1);'>
    <h1 style='color:#1a73e8;'>Painel Proxy UDID - RAILWAY</h1>
    <hr>
    <h3>Adicionar Nova Licença</h3>
    <form action='/add' method='post' style='margin-bottom:30px;'>
        UDID: <input name='udid' required style='padding:10px;width:250px;border:1px solid #ccc;border-radius:5px;'>
        Tempo: <select name='dias' style='padding:10px;border:1px solid #ccc;border-radius:5px;'>
            <option value='7'>7 dias</option>
            <option value='30'>30 dias</option>
        </select>
        <button type='submit' style='padding:10px 20px;background:#28a745;color:white;border:none;border-radius:5px;cursor:pointer;font-weight:bold;'>LIBERAR ACESSO</button>
    </form>
    <table border='0' style='width:100%;border-collapse:collapse;margin-top:20px;'>
        <tr style='background:#1a73e8;color:white;'>
            <th style='padding:12px;text-align:left;'>UDID</th>
            <th style='padding:12px;text-align:left;'>Expiração</th>
            <th style='padding:12px;text-align:left;'>Status</th>
            <th style='padding:12px;text-align:left;'>Ação</th>
        </tr>
        {% for udid, exp_date in licenses.items() %}
        <tr style='border-bottom:1px solid #eee;'>
            <td style='padding:12px;'>{{ udid }}</td>
            <td style='padding:12px;'>{{ exp_date }}</td>
            <td style='padding:12px;'>{{ "Ativo" if exp_date > now else "Expirado" }}</td>
            <td style='padding:12px;'><a href='/del/{{ udid }}' style='color:#d93025;text-decoration:none;font-weight:bold;'>Excluir</a></td>
        </tr>
        {% endfor %}
    </table>
    </div>
</body></html>
"""

@app.route('/')
def index():
    return "Proxy Online. Configure o Wi-Fi com este link e acesse /admin para gerenciar."

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get('logged_in'):
        if request.method == 'POST':
            if request.form['password'] == 'admin123': # Senha padrao
                session['logged_in'] = True
                return redirect(url_for('admin'))
        return "<html><body style='text-align:center;padding-top:100px;'><h1>Painel Administrativo</h1><form method='post'>Senha: <input type='password' name='password'><input type='submit' value='Entrar'></form></body></html>"
    
    licenses = load_licenses()
    now = datetime.now().strftime("%Y-%m-%d")
    return render_template_string(ADMIN_HTML, licenses=licenses, now=now)

@app.route('/add', methods=['POST'])
def add():
    if not session.get('logged_in'): return redirect(url_for('admin'))
    udid = request.form['udid'].strip()
    dias = int(request.form['dias'])
    licenses = load_licenses()
    exp_date = (datetime.now() + timedelta(days=dias)).strftime("%Y-%m-%d")
    licenses[udid] = exp_date
    save_licenses(licenses)
    return redirect(url_for('admin'))

@app.route('/del/<udid>')
def delete(udid):
    if not session.get('logged_in'): return redirect(url_for('admin'))
    licenses = load_licenses()
    if udid in licenses:
        del licenses[udid]
        save_licenses(licenses)
    return redirect(url_for('admin'))

# --- LÓGICA DO PROXY (MITMPROXY) ---
def load_asset(filename):
    path = os.path.join(BASE_DIR, filename)
    if os.path.exists(path):
        with open(path, "r") as f:
            return f.read().strip().replace(" ", "").replace("\n", "").replace("\r", "")
    return ""

indr_data = load_asset("indr.txt")
_3dr_data = load_asset("3dr.txt")
AUTHORIZED_IPS = {}

class ProxyAddon:
    def htb(self, hex_string):
        bytes_array = bytearray()
        for i in range(0, len(hex_string), 2):
            bytes_array.append(int(hex_string[i:i+2], 16))
        return bytes_array.decode("latin-1")

    def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        client_ip = flow.client_conn.peername[0]

        # Rota de Ativacao: http://proxy.local/ativar?udid=XXXX
        if "proxy.local/ativar" in url:
            udid = flow.request.query.get("udid")
            licenses = load_licenses()
            if udid in licenses:
                exp_date = datetime.strptime(licenses[udid], "%Y-%m-%d")
                if datetime.now() < exp_date:
                    AUTHORIZED_IPS[client_ip] = udid
                    flow.response = http.Response.make(200, b"Ativado com Sucesso!", {"Content-Type": "text/plain"})
                    return
            flow.response = http.Response.make(403, b"UDID nao autorizado ou expirado no Painel.", {"Content-Type": "text/plain"})
            return

        # Bloqueio de seguranca
        if client_ip not in AUTHORIZED_IPS:
            if any(domain in url for domain in ["freefire", "garena", "GetBackpack", "fileinfo", "assetindexer"]):
                flow.response = http.Response.make(403, b"Aparelho nao autorizado. Ative seu UDID primeiro.", {"Content-Type": "text/plain"})

    def response(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        client_ip = flow.client_conn.peername[0]
        if client_ip not in AUTHORIZED_IPS: return

        if "/CheckHackBehavior" in url or "/GetMatchmakingBlacklist" in url:
            flow.response = http.Response.make(403, b"L\xc3\xb6i", {"Content-Type": "text/plain"})
        elif "/GetBackpack" in url and flow.request.method == "POST":
            flow.response = http.Response.make(200, b"", {"Content-Type":"application/json"})
        elif "/fileinfo" in url and indr_data:
            flow.response = http.Response.make(200, self.htb(indr_data).encode("latin-1"), {"Content-Type": "application/octet-stream"})
        elif "/assetindexer" in url and _3dr_data:
            flow.response = http.Response.make(200, self.htb(_3dr_data).encode("latin-1"), {"Content-Type": "application/octet-stream"})

def run_proxy():
    # Railway usa a porta definida na variavel de ambiente PORT
    port = int(os.environ.get("PORT", 8080))
    opts = Options(listen_host='0.0.0.0', listen_port=port, confdir="/tmp/.mitmproxy")
    m = DumpMaster(opts)
    m.addons.add(ProxyAddon())
    m.run()

if __name__ == '__main__':
    # Roda o Proxy em uma thread separada
    threading.Thread(target=run_proxy, daemon=True).start()
    # Roda o Painel Web (Flask) em uma porta secundaria ou na mesma se possivel
    # No Railway, usaremos o Mitmproxy como entrada principal
    while True:
        time.sleep(1)
