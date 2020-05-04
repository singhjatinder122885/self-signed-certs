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

def provision_cert():

    get_ingress = "kubectl get ingress --all-namespaces --no-headers"
    result = exec_cmd_w_output(get_ingress)
    if len(result) == 0:
        return

    ingresses = result.decode("utf-8").split("\n")
    logging.debug("ingresses: %s", ingresses)
 
    for ingress in ingresses:
        logging.debug("ingress: %s", ingress)

        if len(ingress) == 0:
            continue

        parts = ingress.split(" ")
        if len(parts) == 0:
            continue

        namespace = parts[0]
        ingress_name = ''
        i = 0
        for part in parts:
            if part.strip() and i != 0:
                ingress_name = part
                break
            else:
                i = i + 1

        logging.debug("Found %s %s", namespace, ingress_name)

        get_secret_name = "kubectl get ingress -o yaml -n " + namespace + " " + ingress_name + " | grep secretName  | cut -f 2 -d :| xargs | sort | uniq"
        result = exec_cmd_w_output(get_secret_name)
        if len(result) == 0:
            continue

        secrets = result.decode("utf-8").split("\n")
        if len(secrets) == 0:
            continue

        for secret in secrets:
            if not secret.strip():
                continue
 
            logging.debug("Checking secret: %s", secret)
            get_secret = "kubectl get secret -n " + namespace + " " + secret + " --no-headers > /dev/null"
            ret = exec_cmd(get_secret)

            if ret != 0:
                logging.info("Secret does not exist")

                get_host_count = "kubectl get ingress -o yaml  -n " + namespace + " " + ingress_name + "  | grep host: | wc -l | xargs"
                result = exec_cmd_w_output(get_host_count)
                if len(result) == 0:
                    continue
                host_count = result.decode("utf-8").strip()

                if host_count == '1':
                    get_host_name = "kubectl get ingress -o yaml -n " + namespace + " " + ingress_name + " | grep host: | cut -f 2 -d : | xargs"
                    result = exec_cmd_w_output(get_host_name)
                    if len(result) == 0:
                        continue
                    host_name = result.decode("utf-8").strip()   
                    if not host_name:
                        continue

                    logging.info("Creating default secret on: %s", host_name)
                    cmd = "rm -f /var/tmp/tls.key /var/tmp/tls.crt"
                    ret = exec_cmd(cmd)

                    ssl = "openssl req -x509 -nodes -days 825 -newkey rsa:2048 -keyout /var/tmp/tls.key -out /var/tmp/tls.crt -subj \"/C=US/ST=CA/L=SF/O=self-signed.cisco.com/CN=" + host_name + "\""
                    ret = exec_cmd(ssl)
                    if ret != 0:
                        continue 
                    
                    create_secret = "kubectl create secret tls " + secret + " --key /var/tmp/tls.key  --cert /var/tmp/tls.crt -n " + namespace
                    ret = exec_cmd(create_secret)
                    if ret != 0:
                        continue 

                    cmd = "rm -f /var/tmp/tls.key /var/tmp/tls.crt"
                    ret = exec_cmd(cmd)
                else: 
                    logging.info("Multiple host found - creation of self signeed cert is not supported")

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