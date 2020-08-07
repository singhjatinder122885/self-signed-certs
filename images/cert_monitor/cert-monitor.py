#!/usr/bin/env python3

#
# Copyright (c) 2020 by cisco Systems, Inc.
#
# cert-monitor
#
# This script monitors referenced secrets in the system and if they are not provisioned then provisions
# a self signed cert 
#
#

import logging
import os
import subprocess
import time
import re

def fn_create_secret(namespace, ingress_name, secret):
    get_host_count = "kubectl get ingress -o yaml  -n " + namespace + " " + ingress_name + "  | grep host: | wc -l | xargs"
    result = exec_cmd_w_output(get_host_count)
    if len(result) == 0:
        logging.info("No hosts associated with the secret. At least a host needs to be associated")
        return
    host_count = result.decode("utf-8").strip()

    if host_count == '1':
        cmd = "kubectl get ingress -o yaml -n " + namespace + " " + ingress_name + " | grep host: | cut -f 2 -d : | xargs"
        result = exec_cmd_w_output(cmd)
        if len(result) == 0:
            logging.info("Host associated with ingress {} not found".format(str(ingress_name)))
            return
        host_name = result.decode("utf-8").strip()   
        if not host_name:
            logging.info("No hosts associated with the secret. At least a host needs to be associated")
            return

        logging.info("Creating default secret on: {}\n".format(str(host_name)))
        cmd = "rm -f /var/tmp/tls.key /var/tmp/tls.crt"
        ret = exec_cmd(cmd)

        ssl = "openssl req -x509 -nodes -days 825 -newkey rsa:2048 -keyout /var/tmp/tls.key -out /var/tmp/tls.crt -subj \"/C=US/ST=CA/L=SF/O=self-signed.cisco.com/CN=" + host_name + "\""
        ret = exec_cmd(ssl)
        if ret != 0:
            logging.info("Failed to create cert using openssl")
            return

        cmd = "kubectl create secret tls " + secret + " --key /var/tmp/tls.key  --cert /var/tmp/tls.crt -n " + namespace
        ret = exec_cmd(cmd)
        if ret != 0:
            logging.info("Failed to create secret")
            return 

        cmd = "rm -f /var/tmp/tls.key /var/tmp/tls.crt"
        ret = exec_cmd(cmd)
    else: 
        logging.info("Multiple host found - creation of self signed cert is not supported\n")

def provision_cert():

    cmd = "kubectl get ingress --all-namespaces --no-headers"
    result = exec_cmd_w_output(cmd)
    if len(result) == 0:
        return

    ingresses = result.decode("utf-8").split("\n")
    logging.info("ingresses: {}\n".format(str(ingresses)))
 
    for ingress in ingresses:
        logging.info("ingress: {}\n".format(str(ingress)))

        if len(ingress) == 0:
            continue

        parts = re.split("\s+",ingress)
        if len(parts) == 0:
            continue

        namespace = parts[0]
        ingress_url = parts[3].strip()
        ingress_name = parts[1]
        logging.info("Found namespace:{}, ingress name:{}, and ingress url:{}\n".format(str(namespace),str(ingress_name),str(ingress_url)))

        cmd = "kubectl get ingress -o yaml -n " + namespace + " " + ingress_name + " | grep secretName  | cut -f 2 -d :| xargs | sort | uniq"
        result = exec_cmd_w_output(cmd)
        if len(result) == 0:
            continue

        secrets = result.decode("utf-8").split("\n")
        secrets=list(filter(None, secrets))
        if len(secrets) == 0:
            continue
        secret = secrets[0]
        if not secret.strip():
            continue

        logging.info("Checking secret: {}\n".format(str(secret)))
        cmd = "kubectl get secret -n " + namespace + " " + secret + " --no-headers > /dev/null"
        ret = exec_cmd(cmd)

        if ret != 0:
            logging.info("Secret does not exist. Execute create secrets .....\n")
            fn_create_secret(namespace, ingress_name, secret)

        else:
            logging.info("Secret exists and it is - {}\n".format(str(secret)))
            cmd = "kubectl get secret -o=json " + str(secret) + " -n " + str(namespace) + " | jq -r '.data[\"tls.crt\"]' | base64 -d | openssl x509 -in /dev/stdin -noout -text | grep 'CN =' |  grep 'Issuer'"
            result = exec_cmd_w_output(cmd)
            ingress_url_search = result.decode("utf-8").split("\n")
            ingress_url_search=list(filter(None, ingress_url_search))
            logging.debug(ingress_url_search)
            if(any(t.__contains__(ingress_url) for t in ingress_url_search)):
                logging.info('Secret {} is configured properly for ingress {}'.format(str(secret),str(ingress_url)))
            else:
                logging.info('Secret {} is configured improperly, Expected ingress:{} in {}\n'.format(str(secret),str(ingress_url),str(ingress_url_search)))
                logging.info("Deleting and recreating the secret for ingress {}\n".format(str(ingress_url)))
                cmd = "kubectl delete secret {} -n {}".format(str(secret), str(namespace))
                ret = exec_cmd(cmd)
                if ret != 0:
                    logging.info("Failed to remove the secret {} for ingress {}, Will try again ......\n".format(str(secret),str(ingress_url)))
                else:
                    fn_create_secret(namespace, ingress_name, secret)


def exec_cmd(cmd):
    result = 1
    try:
        result = os.system(cmd)
    except OSError:
        logging.info("%s", cmd)
    return result
    
def exec_cmd_w_output(cmd):
    result = []
    try:
        result = subprocess.check_output(cmd, shell=True)
    except OSError:
        logging.info("%s", cmd)
    return result

def init_logging():
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', \
                        datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO)

def main():
    init_logging()
    while True:
        provision_cert()
        time.sleep(5)

if __name__ == '__main__':
    main()
