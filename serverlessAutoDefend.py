import os
import urllib3

from datetime import datetime
from prismaapi import PrismaAPI

if os.path.exists(".env"):
    from dotenv import load_dotenv
    load_dotenv()

prisma_api_endpoint = os.getenv("PRISMA_API_ENDPOINT", "https://api.prismacloud.io")
compute_api_endpoint = os.getenv("COMPUTE_API_ENDPOINT", "")
username = os.getenv("PRISMA_USERNAME", "")
password = os.getenv("PRISMA_PASSWORD", "")

DEBUG = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes", "y")
SLEEP = int(os.getenv("SLEEP", "5"))
LIMIT = int(os.getenv("LIMIT", "50"))
PROVIDER = os.getenv("PROVIDER", "aws")
REPORT = os.getenv("REPORT", f"serverlessReport{PROVIDER.upper()}.csv")
HEADER = os.getenv("KEYS", "_id,err,creationTime,type,provider,region,name,lastModified,defended,runtime,architecture,memory,timeout,description,version,resourceGroupName,role,applicationName,accountID,platform").split(",")
PROGRAMMING_LANGS = list(filter(bool, os.getenv("PROGRAMMING_LANGS", "python").split(",")))


headers = {
    "Content-Type": "application/json"
}

COLLECTIONS = [
    {
        "hosts":["*"],
        "images":["*"],
        "labels":["*"],
        "containers":["*"],
        "functions":["*"],
        "namespaces":["*"],
        "appIDs":["*"],
        "accountIDs":["*"],
        "clusters":["*"],
        "name":"All",
        "color":"#5396A7",
        "system": False,
        "prisma": False
    }
]

assert PROVIDER in ("aws", "azure", "gcp")

http = urllib3.PoolManager()

class RequestError(Exception):
    pass



def main():
    prismaAPI = PrismaAPI(
        prisma_api_endpoint,
        compute_api_endpoint,
        username,
        password,
        limit=LIMIT,
        time_sleep=SLEEP,
        debug=DEBUG
    )    
    new_rules = []
    serverless_runtimes = []

    cloud_accounts = prismaAPI.get_all_compute_resources("/api/v1/cloud-scan-rules", "cloudProviders=aws&authMethods=stsTemporaryToken")
    autodefend_rules = prismaAPI.compute_request("/api/v1/settings/serverless-auto-deploy", method="GET")
    prisma_runtimes = prismaAPI.compute_request("/api/v1/static/serverless-runtimes", method="GET")

    # Filter based on programming languages
    if PROGRAMMING_LANGS:
        for runtime in prisma_runtimes:
            for programming_lang in PROGRAMMING_LANGS:
                if runtime.startswith(programming_lang):
                    serverless_runtimes.append(runtime)
    else:
        serverless_runtimes = prisma_runtimes
    

    for cloud_account in cloud_accounts:
        account_found = False
        for rule in autodefend_rules:
            if rule["credentialID"] == cloud_account["credentialId"]:
                account_found = True
                rule["runtimes"] = serverless_runtimes
                break
            
        if not account_found:
            new_rule = {
                "consoleAddr": prismaAPI.get_console_address(),
                "runtimes": serverless_runtimes,
                "awsRegionType":"regular",
                "collections": COLLECTIONS,
                "credentialID": cloud_account["credentialId"],
                "name": cloud_account["credential"]["accountName"],
                "proxy": {
                    "httpProxy":"",
                    "ca":"",
                    "user":"",
                    "noProxy":"",
                    "password":{"encrypted":"","plain":""}
                }
            }
            new_rules.append(new_rule)
    
    all_rules = new_rules + autodefend_rules
    prismaAPI.compute_request("/api/v1/settings/serverless-auto-deploy", body=all_rules, format="raw")



if __name__ == "__main__":
    print(f'Start time: {datetime.now()}')
    main()
    print(f'End time: {datetime.now()}')
