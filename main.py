#! -*- coding: utf-8 -*-

__author__ = 'Eduardo Henrique '
__license__ = "GNU"
__version__ = "2.0.1"

import logging
import yaml
import os
import sys
import time
import argparse
from bs4 import BeautifulSoup as bs
from selenium import webdriver
from frameworks.dopple import VigilantOnion as dp
from frameworks.ragnar import VigilantOnion as ragnar
from frameworks.avaddon import VigilantOnion as avaddon
from frameworks.darkside import VigilantOnion as darkside
from frameworks.egregor import VigilantOnion as egregor
from frameworks.ransomexx import VigilantOnion as ransomexx
from frameworks.ranzyleak import VigilantOnion as ranzyleak

class Main:
    def __init__(self):
        with open('utils/config/config.yml', 'r') as stream:
            data = yaml.load(stream, Loader=yaml.FullLoader)

            self.database_name = data.get("database_name", '')
            self.databas_path = data.get('database_path', '')
            self.debug = data.get('debug', '')
            self.webdriver_path = data.get("webdriver_path", "")
            self.onion_urls = data.get("onion_urls", "")
            self.save_path_log = data.get("save_path_log", "")

        if self.debug:
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S',

            )
        else:
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S',
            )

        self.logger = logging.getLogger(__name__)
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('-f', "--framework", required=True,
                                 help="onion, blog, all")
        self.parser.add_argument('-o', "--output", required=False,
                                 help="Saída do alerta")
        self.args = self.parser.parse_args()
    
        # ..... Onion ...... #
        self.egregor = egregor(save_path_log= self.save_path_log,debug=self.debug, webdriver_path=self.webdriver_path)
        self.ragnar = ragnar(save_path_log= self.save_path_log,debug=self.debug, webdriver_path=self.webdriver_path)
        self.avaddon = avaddon(save_path_log= self.save_path_log,debug=self.debug, webdriver_path=self.webdriver_path)
        self.darkside = darkside(save_path_log= self.save_path_log,debug=self.debug, webdriver_path=self.webdriver_path)        
        self.dopple = dp(save_path_log= self.save_path_log,debug=self.debug, webdriver_path=self.webdriver_path)
        self.ransomexx = ransomexx(save_path_log= self.save_path_log,debug=self.debug, webdriver_path=self.webdriver_path)
        self.ranzyleak = ranzyleak(save_path_log= self.save_path_log,debug=self.debug, webdriver_path=self.webdriver_path)
    
    def call_framework(self):
        try:
            print("""
                _________                           .__                     _______                         
                \_   ___ \ _______ _____   __  _  __|  |    ____  _______   \      \    ____  __  _  __  ______
                /    \  \/ \_  __ \|__  \  \ \/ \/ /|  |  _/ __ \ \_  __ \  /   |   \ _/ __ \ \ \/ \/ / /  ___/
                \     \____ |  | \/ / __ \_ \     / |  |__\  ___/  |  | \/ /    |    \|  ___/  \     /  \___ \ 
                 \______  / |__|   (____  /  \/\_/  |____/ \___  > |__|    \____|__  / \___  >  \/\_/  /____  >
                        \/              \/                     \/                  \/      \/               \/         
            """)
            
            if self.args.framework.lower() == "onion":
                self.ranzyleak.start
                self.ransomexx.start
                self.egregor.start
                self.darkside.start
                self.avaddon.start
                self.ragnar.start
                self.dopple.start

            if self.args.framework.lower() == "surface":
                self.logger.info("[ALERTA] Esta funcionalidade está em desenvolvimento, roda denovo e escolha -f onion...")
                time.sleep(4)

            if self.args.framework.lower() == "all":
                self.ranzyleak.start
                self.ransomexx.start
                self.dopple.start
                self.ragnar.start
                self.avaddon.start
                self.darkside.start
                self.egregor.start             
        
        except Exception as error:
            self.logger.info(f"[ERROR] Não foi possível realizar a chamada nos frameworks {error}")

if __name__ == "__main__":
    while True:
        init = Main()
        init.call_framework()