#!/usr/bin/env python3

import re
import sys

try:
    argv = sys.argv
    if len(argv) != 3:
        print("Uso: python3 ioc-to-cdblist.py entrada.txt saida.cdb")
        exit(1)

    # Regex para detectar IPs com ou sem máscara
    ip_regex = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?$')
    hash_regex = re.compile(r'^[a-fA-F0-9]{32,64}$')  # MD5, SHA1, SHA256
    domain_regex = re.compile(
        r'^([a-zA-Z0-9][a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,}$'
    )

    cdir_conversion = {"32": 4, "24": 3, "16": 2, "8": 1}
    first_time = True

    with open(argv[1], 'r') as fi, open(argv[2], 'w') as fo:
        for line in fi:
            clean_line = line.strip()

            # Detectar IP
            match = ip_regex.match(clean_line)
            if match:
                ip = match.group(1)
                mask = match.group(2)
                if mask and mask in cdir_conversion:
                    ip_parts = ip.split('.')
                    ip = '.'.join(ip_parts[:cdir_conversion[mask]])
                    if mask != "32":
                        ip += "."
                elif mask and mask not in cdir_conversion:
                    continue
                output = ip + ":"

            # Detectar hash (MD5, SHA1, SHA256)
            elif hash_regex.match(clean_line):
                output = clean_line + ":"

            # Detectar domínio
            elif domain_regex.match(clean_line):
                output = clean_line.lower() + ":"

            else:
                continue  # Linha não reconhecida

            if first_time:
                fo.write(output)
                first_time = False
            else:
                fo.write("\n" + output)

    print(f"[{argv[1]}] -> [{argv[2]}]")

except Exception as e:
    print(f"Erro:\n{e}\nEncerrando...")
    exit(1)
