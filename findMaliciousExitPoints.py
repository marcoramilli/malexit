#!/usr/bin/env python2

#===============================================================================#
#               THIS IS NOT A PRODUCTION RELEASED SOFTWARE                      #
#===============================================================================#
# Purpose of finMaliciousRelayPoints is to proof the way it's possible to       #
# discover TOR malicious Relays Points. Please do not use it in any production  #
# environment                                                                   #
# Author: Marco Ramilli                                                         #
# eMail: XXXXXXXX                                                               #
# WebSite: marcoramilli.blogspot.com                                            #
# Use it at your own                                                            #
#===============================================================================#

#==============================Disclaimer: =====================================#
#THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR             #
#IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED                 #
#WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE         #
#DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,             #
#INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES             #
#(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR             #
#SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)             #
#HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,            #
#STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING          #
#IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE             #
#POSSIBILITY OF SUCH DAMAGE.                                                    #
#===============================================================================#




#-------------------------------------------------------------------------------
#------------------- GENERAL SECTION -------------------------------------------
#-------------------------------------------------------------------------------
import StringIO
import tempfile
import time
import hashlib
import traceback
from   geoip         import  geolite2
import stem.control

TRUSTED_HOP_FINGERPRINT = '379FB450010D17078B3766C2273303C358C3A442' #trusted hop
SOCKS_PORT              = 9050
CONNECTION_TIMEOUT      = 30  # timeout before we give up on a circuit

#-------------------------------------------------------------------------------
#---------------- File Patching Section ----------------------------------------
#-------------------------------------------------------------------------------
import pycurl

check_files               = {
                                "http://live.sysinternals.com/psexec.exe",
                                "http://live.sysinternals.com/psexec.exe",
                                "http://live.sysinternals.com/psping.exe", }
check_files_patch_results = []

class File_Check_Results:
    """
    Analysis Results against File Patching
    """
    def __init__(self, url, filen, filepath, exitnode, found_hash):
        self.url           = url
        self.filename      = filen
        self.filepath      = filepath
        self.exitnode      = exitnode
        self.filehash      = found_hash


#-------------------------------------------------------------------------------
#------------------- DNS Poison Section ----------------------------------------
#-------------------------------------------------------------------------------
import dns.resolver
import socks
import socket

check_domain_poison_results = []
domains                     = {
                                 "www.youporn.com",
                                 "youporn.com",
                                 "www.torproject.org",
                                 "www.wikileaks.org",
                                 "www.i2p2.de",
                                 "torrentfreak.com",
                                 "blockchain.info",
}

class Domain_Poison_Check:
    """
    Analysis Results against Domain Poison
    """
    def __init__(self, domain):
        self.domain  = domain
        self.address = []
        self.path    = []

    def pushAddr(self, add):
        self.address.append(add)

    def pushPath(self, path):
        self.path = path

#-------------------------------------------------------------------------------
#------------------- SSL Sltrip Section ----------------------------------------
#-------------------------------------------------------------------------------
import OpenSSL
import ssl

check_ssl_strip_results   = []
ssl_strip_monitored_urls = {
                            "www.google.com",
                            "www.microsoft.com",
                            "www.apple.com",
                            "www.bbc.com",
}

class SSL_Strip_Check:
    """
    Analysis Result against SSL Strip
    """
    def __init__(self, domain, public_key, serial_number):
        self.domain        = domain
        self.public_key    = public_key
        self.serial_number = serial_number


#-------------------------------------------------------------------------------
#----------------     Starting Coding   ----------------------------------------
#-------------------------------------------------------------------------------


def sslCheckOriginal():
    """
    Download the original Certificate without TOR connection
    """
    print('[+] Populating SSL for later check')
    for url in ssl_strip_monitored_urls:
        try:
            cert = ssl.get_server_certificate((str(url), 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            p_k  = x509.get_pubkey()
            s_n  = x509.get_serial_number()

            print('[+] Acquired Certificate: %s' % url)
            print('    |_________> serial_number %s' % s_n)
            print('    |_________> public_key %s' % p_k)

            check_ssl_strip_results.append(SSL_Strip_Check(url, p_k, s_n))

        except Exception as err:
            print('[-] Error While Acquiring certificats on setup phase !')
            traceback.print_exc()
    return time.time()


def fileCheckOriginal():
    """
    Downloading file ORIGINAL without TOR
    """

    print('[+] Populating File Hasing for later check')
    for url in check_files:
        try:
            data = query(url)
            file_name = url.split("/")[-1]
            _,tmp_file = tempfile.mkstemp(prefix="exitmap_%s_" % file_name)

            with open(tmp_file, "wb") as fd:
                fd.write(data)
                print('[+] Saving File  \"%s\".' % tmp_file)
                check_files_patch_results.append( File_Check_Results(url, file_name, tmp_file, "NO", sha512_file(tmp_file)) )
                print('[+] First Time we see the file..')
                print('    |_________> exitnode : None'       )
                print('    |_________> :url:  %s' % str(url)     )
                print('    |_________> :filePath:  %s' % str(tmp_file))
                print('    |_________> :file Hash: %s' % str(sha512_file(tmp_file)))
        except Exception as err:
                print('[-] Error ! %s' % err)
                traceback.print_exc()
                pass
    return time.time()


def resolveOriginalDomains():
    """
        Resolving DNS For original purposes
    """
    print('[+] Populating Domain Name Resolution for later check ')

    try:
        for domain in domains:
            response = dns.resolver.query(domain)
            d = Domain_Poison_Check(domain)
            print('[+] Domain: %s' % domain)
            for record in response:
                print(' |____> maps to %s.' % (record.address))
                d.pushAddr(record)
            check_domain_poison_results.append(d)
        return time.time()
    except Exception as err:
        print('[+] Exception: %s' % err)
        traceback.print_exc()
        return time.time()


def query(url):
  """
  Uses pycurl to fetch a site using the proxy on the SOCKS_PORT.
  """
  output = StringIO.StringIO()
  query = pycurl.Curl()
  query.setopt(pycurl.URL, url)
  query.setopt(pycurl.PROXY, 'localhost')
  query.setopt(pycurl.PROXYPORT, SOCKS_PORT)
  query.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
  query.setopt(pycurl.CONNECTTIMEOUT, CONNECTION_TIMEOUT)
  query.setopt(pycurl.WRITEFUNCTION, output.write)

  try:
    query.perform()
    return output.getvalue()
  except pycurl.error as exc:
    raise ValueError("Unable to reach %s (%s)" % (url, exc))



def scan(controller, path):
  """
  Scan Tor Relays Point to find File Patching
  """

  def attach_stream(stream):
    if stream.status == 'NEW':
      try:
        controller.attach_stream(stream.id, circuit_id)
        #print('[+] New Circuit id (%s) attached and ready to be used!' % circuit_id)
      except Exception as err:
        controller.remove_event_listener(attach_stream)
        controller.reset_conf('__LeaveStreamsUnattached')

  try:

    print('[+] Creating a New TOR circuit based on path: %s' % path)
    circuit_id = controller.new_circuit(path, await_build = True)
    controller.add_event_listener(attach_stream, stem.control.EventType.STREAM)
    controller.set_conf('__LeaveStreamsUnattached', '1')  # leave stream management to us
    start_time = time.time()

    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
    socket.socket = socks.socket

    ip = query('http://ip.42.pl/raw')
    if ip is not None:
        country  = geolite2.lookup( str(ip) ).country
        print('\n \n')
        print('[+] Performing FilePatch,  DNS Spoofing and Certificate Checking\
              passing through --> %s (%s) \n \n' % (str(ip), str(country))  )

    time_FileCheck = fileCheck(path)
    print('[+] FileCheck took: %0.2f seconds'  % ( time_FileCheck - start_time))

    #time_CertsCheck  = certsCheck(path)
    #print('[+] CertsCheck took: %0.2f seconds' % ( time_DNSCheck - start_time))

    time_DNSCheck  = dnsCheck(path)
    print('[+] DNSCheck took: %0.2f seconds'   % ( time_DNSCheck - start_time))

  except Exception as  err:
    print('[-] Circuit creation error: %s' % path)

  return time.time() - start_time

def certsCheck(path):
    """
    SSL Strip detection
    TODO: It's still a weak control. Need to collect and to compare public_key()
    """
    print('[+] Checking Certificates')
    try:
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
        socket.socket = socks.socket

        for url in ssl_strip_monitored_urls:
            cert = ssl.get_server_certificate((str(url), 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            p_k  = x509.get_pubkey()
            s_n  = x509.get_serial_number()
            for stored_cert in check_ssl_strip_results:
                if str(url) == str(stored_cert.domain):
                    if str(stored_cert.serial_number) != str(s_n):
                        print('[+] ALERT Found SSL Strip on uri (%s) through path %s ' % (url, path))
                        break
                    else:
                        print('[+] Certificate Check seems to be OK for %s' % url)

    except Exception as err:
        print('[-] Error: %s' % err)
        traceback.print_exc()

    socket.close()
    return time.time()

def dnsCheck(path):
    """
    DNS Poisoning Check
    """
    try:
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
        socket.socket = socks.socket

        print('[+] Checking DNS ')
        for domain in domains:
            ipv4 = socket.gethostbyname(domain)
            for p_d in check_domain_poison_results:
                if str(p_d.domain) == str(domain):
                    found = False
                    for d_ip in p_d.address:
                        if str(ipv4) == str(d_ip):
                            found = True
                            break
                    if found == False:
                        print('[+] ALERT:DNS SPOOFING FOUND: name: %s ip: %s  (path: %s )' % (domain, ipv4, path) )
                    else:
                        print('[+] Check DNS (%s) seems to be OK' % domain)
    except Exception as err:
        print('[-] Error: %s' % err)
        traceback.print_exc()

    socket.close()
    return time.time()


def fileCheck(path):
    """
    Downloading file through TOR circuits doing the hashing
    """
    print('[+] Checking For File patching ')
    for url in check_files:
        try:
            #File Rereive
            data = query(url)
            file_name = url.split("/")[-1]
            _,tmp_file = tempfile.mkstemp(prefix="exitmap_%s_" % file_name)
            with open(tmp_file, "wb") as fd:
                fd.write(data)
                for i in check_files_patch_results:
                    if str(i.url) == str(url):
                        if str(i.filehash) != str(sha512_file(tmp_file)):
                            print('[+] ALERT File Patch FOUND !')
                            print('    | exitnode : %s' % str(i.exitnode)      )
                            print('    |_________> url: %s' % str(i.url)        )
                            print('    |_________> filePath: %s' % str(i.filepath)   )
                            print('    |_________> fileHash: %s' % str(i.filehash)   )
                            #check_files_patch_results.append( File_Check_Results(url, file_name, tmp_file, path, sha512_file(tmp_file)) )
                        else :
                            print('[+] File (%s) seems to be ok' % i.url)
                        break

        except Exception as err:
                print('[-] Error ! %s' % err)
                traceback.print_exc()
                pass
    return time.time()


def sha512_file(file_name):
    """
    Calculate SHA512 over the given file.
    """

    hash_func = hashlib.sha256()

    with open(file_name, "rb") as fd:
        hash_func.update(fd.read())

    return hash_func.hexdigest()


if __name__ == '__main__':

    start_analysis = time.time()
    print("""

          |=====================================================================|
          | Find Malicious Relay Nodes is a python script made for checking three|
          | unique kind of frauds such as:                                      |
          | (1) File Patching                                                   |
          | (2) DNS Poison                                                      |
          | (3) SSL Stripping (MITM SSL)                                        |
          |=====================================================================|

          """)

    print("""
          |=====================================================================|
          |                 Initialization Phase                                |
          |=====================================================================|
          """)
    dns_setup_time             = resolveOriginalDomains()
    print('[+] DNS Setup Finished: %0.2f' % (dns_setup_time - start_analysis))
    file_check_original_time   = fileCheckOriginal()
    print('[+] File Setup Finished: %0.2f' % (file_check_original_time - start_analysis))
    ssl_checking_original_time = sslCheckOriginal()
    print('[+] Acquiring Certificates  Setup Finished: %0.2f' % (ssl_checking_original_time - start_analysis))

    print("""
          |=====================================================================|
          |                 Analysis  Phase                                     |
          |=====================================================================|
          """)

    print('[+] Connecting and Fetching possible Relays ...')
    with stem.control.Controller.from_port() as controller:
      controller.authenticate()

      net_status = controller.get_network_statuses()


      for descriptor in net_status:
        try:
          fingerprint = descriptor.fingerprint

          print('[+] Selecting a New Exit Point:')
          print('[+] |_________> FingerPrint: %s ' % fingerprint)
          print('[+] |_________> Flags: %s ' % descriptor.flags)
          print('[+] |_________> Exit_Policies: %s ' % descriptor.exit_policy)

          if 'EXIT' in (flag.upper() for flag in descriptor.flags):
              print('[+] Found Exit Point. Performing Scan through EXIT: %s' % fingerprint)
              if None == descriptor.exit_policy:
                  print('[+] No Exit Policies found ... no certs checking')
                  time_taken = scan(controller, [TRUSTED_HOP_FINGERPRINT, fingerprint])
          else:
              #print('[+] Not Exit Point found. Using it as Relay passing to TRUST Exit Point')
              pass
              #time_taken = scan(controller, [fingerprint, TRUSTED_HOP_FINGERPRINT])
          #print('[+] Finished Analysis for %s finished  => %0.2f seconds' % (fingerprint, time_taken))

        except Exception as exc:
            print('[-] Exception on  FingerPrint: %s => %s' % (fingerprint, exc))
            traceback.print_exc()
            pass


