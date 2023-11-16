import logging
import os
import requests
import sys

import urllib3
urllib3.disable_warnings()
requests.packages.urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

session = requests.Session()
session.verify = False

from dotenv import load_dotenv
from pyunifi.controller import Controller as UnifiController
from requests.auth import HTTPBasicAuth

load_dotenv()

logging.basicConfig(stream=sys.stdout, level=logging.INFO)


unifi: dict = {
    "host": os.environ.get("UNIFI_HOST"),
    "port": os.environ.get("UNIFI_PORT", 443),
    "username": os.environ.get("UNIFI_USERNAME"),
    "password": os.environ.get("UNIFI_PASSWORD"),
    "version": os.environ.get("UNIFI_VERSION", "UDMP-unifiOS"),
    "site_id": os.environ.get("UNIFI_SITE", "default"),
    "ssl_verify": False
}

adguard: dict =  {
    "host": os.environ.get("ADGUARD_HOST"),
    "port": os.environ.get("ADGUARD_PORT", 3000),
    "username": os.environ.get("ADGUARD_USERNAME"),
    "password": os.environ.get("ADGUARD_PASSWORD"),
    "protocol": os.environ.get("ADGUARD_PROTOCOL", "http")
}

class Client:

    name: str
    identifiers: list[str]

    def __init__(self, name: str, identifiers: list[str]) -> None:
        self.name = name
        self.identifiers = identifiers

class AdguardController:

    host: str = None
    port: int = None
    username: str = None
    password: str = None
    protocol: str = None
    
    def __init__(self, host: str, username: str, password: str, port: int, protocol: str) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.protocol = protocol

        self.validate()
    
    @property
    def base_url(self) -> str:
        return f"{self.protocol}://{self.host}:{self.port}"
    
    @property
    def auth(self) -> HTTPBasicAuth:
        return HTTPBasicAuth(username=self.username, password=self.password)

    def get_clients(self) -> list[Client]:
        url = f"{self.base_url}/control/clients"
        r = requests.get(url=url, auth= self.auth)
        r.raise_for_status()
        j = r.json()

        clients = []
        if "clients" in j.keys():
            clients = [ Client(name=client["name"], identifiers=client["ids"]) for client in j["clients"]]
        return clients

    def overwrite_client(self, name:str, new_name: str, ip: str):
        self.delete_client(name=name)
        self.add_client(name=new_name, ip=ip)

    def delete_client(self, name: str):
        delete_url = f"{self.base_url}/control/clients/delete"
        body = {
            "name": name
        }
        r = requests.post(url=delete_url, auth=self.auth, json=body)
        r.raise_for_status()

    def add_client(self, name: str, ip: str):
        logging.info(f"Adding IP: {ip}, Unifi Name: {name}")
        add_url = f"{self.base_url}/control/clients/add"
        body = {
            "name": name,
            "ids": [
                ip
            ],
            "use_global_settings": True,
            "filtering_enabled": False,
            "parental_enabled": False,
            "safebrowsing_enabled": False,
            "safe_search": {
                "enabled": False,
                "bing": True,
                "duckduckgo": True,
                "google": True,
                "pixabay": True,
                "yandex": True,
                "youtube": True
            },
            "use_global_blocked_services": True,
            
            "blocked_services": [],
            "upstreams": [],
            "tags": [],
            "ignore_querylog": False,
            "ignore_statistics": False
            }

        r = requests.post(url=add_url, auth=self.auth, json=body)
        r.raise_for_status()

    def validate(self):

        url = f"{self.base_url}/control/status"
        
        r = requests.get(url=url, auth=self.auth)
        r.raise_for_status()
        j = r.json()
        logging.info(f"Connected to Adguard: {self.host} (version: {j['version']})")

class UnifiAdguardSyncClient:

    unifi: UnifiController
    adguard: AdguardController

    unifi_clients: list[Client] = []
    adguard_clients: list[Client] = []

    def __init__(self, unifi: UnifiController, adguard: AdguardController) -> None:
        self.unifi = unifi
        self.adguard = adguard
    
    def get_unifi_clients(self) -> list[Client]:
        clients = self.unifi.get_clients()
        for client in clients:
            obj = {}
            keys_to_check = ["name", "hostname", "ip","mac"]
            for key in keys_to_check:
                if key in client.keys():
                    if client[key] != "" and client[key] != None:
                        obj[key] = client[key]

            if "name" not in obj.keys():
                if "hostname" in obj.keys():
                    obj["name"] = obj["hostname"]
                else:
                    obj["name"] = obj["mac"]

            c = Client(obj["name"], [obj["ip"]])
            self.unifi_clients.append(c)

    def get_adguard_clients(self):
        clients = self.adguard.get_clients()
        self.adguard_clients = clients
        return clients

    def sync(self):
        self.get_unifi_clients()
        self.get_adguard_clients()
        

        logging.info(f"Found {len(self.unifi_clients)} Unifi Client(s)")
        logging.info(f"Found {len(self.adguard_clients)} Adguard Client(s)")

        unifi_client_names = [uc.name for uc in self.unifi_clients]
        duplicates = {i:unifi_client_names.count(i) for i in unifi_client_names if unifi_client_names.count(i) > 1}
        for duplicate, nr in duplicates.items():
            logging.info(f"Found {nr} device(s) named {duplicate}, please fix in Unifi")
        

        for uc in self.unifi_clients:
            if uc.name in duplicates.keys():
                logging.info(f"Skipping {uc.name}")
                continue
            synced = False
            uc_ip = uc.identifiers[0]
            for ac in self.adguard_clients:
                if uc_ip in ac.identifiers:
                    logging.info(f"Found IP: {uc_ip}, Unifi Name: {uc.name}, Adguard Name: {ac.name}")
                    if uc.name != ac.name:
                        self.adguard.overwrite_client(name=ac.name, new_name=uc.name, ip=uc_ip)
                    synced = True
                if synced:
                    continue
            if not synced:
                self.adguard.add_client(name=uc.name, ip=uc_ip)





def main():
    
    logging.info("Starting sync")

    u = UnifiController(**unifi)
    logging.info("Starting sync")
    a = AdguardController(**adguard)
    
    
    uasc = UnifiAdguardSyncClient(unifi=u, adguard=a)
    uasc.sync()
    logging.info("Finished sync")
    


if __name__ == "__main__":
    main()